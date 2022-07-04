/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2020 Lennert Buytenhek
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version
 * 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License version 2.1 along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street - Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#define PACKAGE_VERSION		"0.1"

#define _FILE_OFFSET_BITS	64
#define _GNU_SOURCE

#define FUSE_USE_VERSION	32

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <fuse.h>
#include <gcrypt.h>
#include <iv_avl.h>
#include <iv_list.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include "reposet.h"
#include "rw.h"

#define MAX_DIRTY_CHUNKS	512

struct repomount_file_info {
	int		fd;
	uint64_t	numchunks;
	uint64_t	size;
	uint32_t	size_firstchunk;

	int		writeable;

	pthread_mutex_t		lock;
	struct iv_avl_tree	dirty_chunks;
	uint64_t		num_dirty_chunks;
	struct iv_list_head	lru;

	bool		wrote_empty_chunk;
	uint8_t		empty_chunk_hash[];
};

struct dirty_chunk {
	struct iv_avl_node	an;
	uint64_t		chunk_index;
	uint32_t		length;

	struct iv_list_head	list_lru;

	struct timespec		last_write;
	uint8_t			buf[];
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static struct reposet rs;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static int repomount_getattr(const char *path, struct stat *buf,
			     struct fuse_file_info *fi)
{
	struct iv_list_head *lh;
	int fd;
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "getattr called with [%s]\n", path);
		return -ENOENT;
	}

	if (path[1] == 0) {
		iv_list_for_each (lh, &rs.repos) {
			struct repo *r;

			r = iv_container_of(lh, struct repo, list);

			if (fstat(r->imagedir, buf) < 0) {
				perror("fstat");
				continue;
			}

			return 0;
		}

		return -ENOENT;
	}

	fd = reposet_open_image(&rs, path + 1, O_RDONLY | O_NOFOLLOW);
	if (fd < 0)
		return fd;

	ret = reposet_stat_image(&rs, fd, NULL, buf);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	close(fd);

	return 0;
}

static int repomount_readlink(const char *path, char *buf, size_t bufsiz)
{
	struct iv_list_head *lh;

	if (path[0] != '/') {
		fprintf(stderr, "readlink called with [%s]\n", path);
		return -ENOENT;
	}

	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;
		int ret;

		r = iv_container_of(lh, struct repo, list);

		ret = readlinkat(r->imagedir, path + 1, buf, bufsiz);
		if (ret >= 0) {
			if (bufsiz && ret == bufsiz)
				ret--;
			buf[ret] = 0;
			return 0;
		}

		if (ret < 0 && errno != ENOENT)
			return -errno;
	}

	return -ENOENT;
}

static int repomount_truncate(const char *path, off_t length,
			      struct fuse_file_info *fi)
{
	return -EINVAL;
}

static int compare_dirty_chunks(const struct iv_avl_node *_a,
				const struct iv_avl_node *_b)
{
	const struct dirty_chunk *a;
	const struct dirty_chunk *b;

	a = iv_container_of(_a, struct dirty_chunk, an);
	b = iv_container_of(_b, struct dirty_chunk, an);

	if (a->chunk_index < b->chunk_index)
		return -1;
	if (a->chunk_index > b->chunk_index)
		return 1;

	return 0;
}

static int repomount_open(const char *path, struct fuse_file_info *fi)
{
	int writeable;
	int fd;
	struct image_info info;
	struct repomount_file_info *fh;
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "open called with [%s]\n", path);
		return -ENOENT;
	}

	writeable = !((fi->flags & O_ACCMODE) == O_RDONLY);

	fd = reposet_open_image(&rs, path + 1, writeable ? O_RDWR : O_RDONLY);
	if (fd < 0)
		return fd;

	ret = reposet_stat_image(&rs, fd, &info, NULL);
	if (ret < 0)
		return ret;

	fh = malloc(sizeof(*fh) + hash_size);
	if (fh == NULL) {
		close(fd);
		return -ENOMEM;
	}

	fh->fd = fd;
	fh->numchunks = info.numchunks;
	fh->size = info.size;
	fh->size_firstchunk = info.size_firstchunk;

	fh->writeable = writeable;

	pthread_mutex_init(&fh->lock, NULL);
	INIT_IV_AVL_TREE(&fh->dirty_chunks, compare_dirty_chunks);
	fh->num_dirty_chunks = 0;
	INIT_IV_LIST_HEAD(&fh->lru);

	fh->wrote_empty_chunk = false;

	fi->fh = (int64_t)fh;

	return 0;
}

static struct dirty_chunk *
__find_dirty_chunk(struct repomount_file_info *fh, uint64_t chunk_index)
{
	struct iv_avl_node *an;

	an = fh->dirty_chunks.root;
	while (an != NULL) {
		struct dirty_chunk *c;

		c = iv_container_of(an, struct dirty_chunk, an);
		if (chunk_index == c->chunk_index)
			return c;

		if (chunk_index < c->chunk_index)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int repomount_read(const char *path, char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	ssize_t processed;

	if (offset < 0)
		return -EINVAL;
	if (offset >= fh->size)
		return 0;

	if (size > SSIZE_MAX)
		size = SSIZE_MAX;
	if (offset + size > fh->size)
		size = fh->size - offset;

	pthread_mutex_lock(&fh->lock);

	processed = 0;
	while (size) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		size_t chunk_toread;
		struct dirty_chunk *c;
		int ret;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		chunk_toread = fh->size_firstchunk - chunk_offset;
		if (chunk_toread > size)
			chunk_toread = size;

		c = __find_dirty_chunk(fh, chunk_index);
		if (c == NULL) {
			uint8_t hash[hash_size];
			int fd;

			pthread_mutex_unlock(&fh->lock);

			if (xpread(fh->fd, hash, hash_size,
				   chunk_index * hash_size) != hash_size)
				goto eio;

			fd = reposet_open_chunk(&rs, hash);
			if (fd < 0)
				goto eio;

			ret = xpread(fd, buf, chunk_toread, chunk_offset);
			if (ret <= 0) {
				close(fd);
				goto eio;
			}

			close(fd);

			pthread_mutex_lock(&fh->lock);
		} else {
			memcpy(buf, c->buf + chunk_offset, chunk_toread);
			ret = chunk_toread;
		}

		buf += ret;
		size -= ret;
		offset += ret;

		processed += ret;
	}

	pthread_mutex_unlock(&fh->lock);

	return processed;

eio:
	return processed ? processed : -EIO;
}

static void write_dirty_chunk(struct repomount_file_info *fh,
			      struct dirty_chunk *c, uint8_t *hash)
{
	struct timespec times[2];
	int copies;

	gcry_md_hash_buffer(hash_algo, hash, c->buf, c->length);

	times[0].tv_sec = 0;
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = c->last_write.tv_sec;
	times[1].tv_nsec = c->last_write.tv_nsec;

	copies = reposet_write_chunk(&rs, hash, c->buf, c->length, times);
	if (copies == 0) {
		fprintf(stderr, "write_dirty_chunk: no copies written\n");
		abort();
	}
}

static void __flush_dirty_chunk(struct repomount_file_info *fh,
				struct dirty_chunk *c)
{
	uint8_t hash[hash_size];
	int ret;

	write_dirty_chunk(fh, c, hash);

	ret = xpwrite(fh->fd, hash, hash_size, c->chunk_index * hash_size);
	if (ret != hash_size) {
		if (ret >= 0)
			fprintf(stderr, "__flush_dirty_chunk: short write\n");
		abort();
	}

	iv_avl_tree_delete(&fh->dirty_chunks, &c->an);
	fh->num_dirty_chunks--;
	iv_list_del(&c->list_lru);

	free(c);
}

static int __flush_one_dirty_chunk(struct repomount_file_info *fh)
{
	if (!iv_list_empty(&fh->lru)) {
		struct dirty_chunk *c;

		c = iv_container_of(fh->lru.next, struct dirty_chunk,
				    list_lru);
		__flush_dirty_chunk(fh, c);

		return 1;
	}

	return 0;
}

static uint32_t
compute_chunk_size(struct repomount_file_info *fh, uint64_t chunk_index)
{
	uint32_t chunk_size;

	chunk_size = fh->size_firstchunk;
	if (chunk_index == fh->numchunks - 1)
		chunk_size = fh->size - (fh->numchunks - 1) * chunk_size;

	return chunk_size;
}

static struct dirty_chunk *
__get_dirty_chunk(struct repomount_file_info *fh, uint64_t chunk_index,
		  int read_backing_data)
{
	struct dirty_chunk *c;
	uint32_t chunk_size;

	c = __find_dirty_chunk(fh, chunk_index);
	if (c != NULL) {
		iv_list_del(&c->list_lru);
		iv_list_add_tail(&c->list_lru, &fh->lru);
		clock_gettime(CLOCK_REALTIME, &c->last_write);
		return c;
	}

	while (fh->num_dirty_chunks >= MAX_DIRTY_CHUNKS) {
		if (!__flush_one_dirty_chunk(fh))
			break;
	}

	c = malloc(sizeof(*c) + fh->size_firstchunk);
	if (c == NULL)
		return NULL;

	chunk_size = compute_chunk_size(fh, chunk_index);

	if (read_backing_data) {
		uint8_t hash[hash_size];
		int ret;
		int fd;

		ret = xpread(fh->fd, hash, hash_size, chunk_index * hash_size);
		if (ret != hash_size) {
			free(c);
			return NULL;
		}

		fd = reposet_open_chunk(&rs, hash);
		if (fd < 0) {
			free(c);
			return NULL;
		}

		ret = xpread(fd, c->buf, chunk_size, 0);
		if (ret != chunk_size) {
			if (ret >= 0) {
				fprintf(stderr, "get_dirty_chunk: short "
						"read of %d\n", ret);
			}
			abort();
		}

		close(fd);

		if (chunk_size < fh->size_firstchunk) {
			memset(c->buf + chunk_size, 0,
			       fh->size_firstchunk - chunk_size);
		}
	} else {
		memset(c->buf, 0, fh->size_firstchunk);
	}

	c->chunk_index = chunk_index;
	c->length = chunk_size;
	iv_list_add(&c->list_lru, &fh->lru);
	clock_gettime(CLOCK_REALTIME, &c->last_write);

	iv_avl_tree_insert(&fh->dirty_chunks, &c->an);
	fh->num_dirty_chunks++;

	return c;
}

static int repomount_write(const char *path, const char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	ssize_t processed;

	if (!fh->writeable)
		return -EBADF;

	if (offset < 0)
		return -EINVAL;
	if (offset >= fh->size)
		return -ENOSPC;

	if (size > SSIZE_MAX)
		size = SSIZE_MAX;
	if (offset + size > fh->size)
		size = fh->size - offset;

	pthread_mutex_lock(&fh->lock);

	processed = 0;
	while (size) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		uint32_t chunk_size;
		struct dirty_chunk *c;
		size_t chunk_towrite;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		chunk_size = compute_chunk_size(fh, chunk_index);

		if (chunk_offset != 0 || size < chunk_size)
			c = __get_dirty_chunk(fh, chunk_index, 1);
		else
			c = __get_dirty_chunk(fh, chunk_index, 0);

		if (c == NULL)
			goto eio;

		chunk_towrite = chunk_size - chunk_offset;
		if (chunk_towrite > size)
			chunk_towrite = size;

		memcpy(c->buf + chunk_offset, buf, chunk_towrite);

		buf += chunk_towrite;
		size -= chunk_towrite;
		offset += chunk_towrite;

		processed += chunk_towrite;
	}

	pthread_mutex_unlock(&fh->lock);

	return processed;

eio:
	pthread_mutex_unlock(&fh->lock);

	return processed ? processed : -EIO;
}

static int repomount_statfs(const char *path, struct statvfs *buf)
{
	struct iv_list_head *lh;

	if (path[0] != '/') {
		fprintf(stderr, "statfs called with [%s]\n", path);
		return -ENOENT;
	}

	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;
		int ret;

		r = iv_container_of(lh, struct repo, list);

		ret = fstatvfs(r->chunkdir, buf);
		if (ret < 0)
			continue;

		return 0;
	}

	return -EIO;
}

static void flush_file(struct repomount_file_info *fh)
{
	int dirty_chunks;
	struct iv_avl_node *an;

	pthread_mutex_lock(&fh->lock);

	dirty_chunks = 0;
	iv_avl_tree_for_each (an, &fh->dirty_chunks)
		dirty_chunks++;

	if (dirty_chunks) {
		int i;

		i = 0;
		while (!iv_avl_tree_empty(&fh->dirty_chunks)) {
			struct dirty_chunk *c;

			fprintf(stderr, "\rfd %d: flushing chunk %d/%d",
				fh->fd, ++i, dirty_chunks);

			an = iv_avl_tree_min(&fh->dirty_chunks);

			c = iv_container_of(an, struct dirty_chunk, an);
			__flush_dirty_chunk(fh, c);
		}

		fprintf(stderr, "\n");
	}

	pthread_mutex_unlock(&fh->lock);
}

static int repomount_release(const char *path, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;

	flush_file(fh);

	close(fh->fd);
	free(fh);

	return 0;
}

static int repomount_fsync(const char *path, int datasync,
			   struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;

	flush_file(fh);

	return 0;
}

struct dentry {
	struct iv_avl_node	an;
	char			name[0];
};

static int compare_dentries(const struct iv_avl_node *_a,
			    const struct iv_avl_node *_b)
{
	struct dentry *a = iv_container_of(_a, struct dentry, an);
	struct dentry *b = iv_container_of(_b, struct dentry, an);

	return strcmp(a->name, b->name);
}

static int find_dentry(struct iv_avl_tree *dentries, const char *name)
{
	struct iv_avl_node *an;

	an = dentries->root;
	while (an != NULL) {
		struct dentry *d;
		int ret;

		d = iv_container_of(an, struct dentry, an);

		ret = strcmp(name, d->name);
		if (ret == 0)
			return 1;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return 0;
}

static int repomount_readdir(const char *path, void *buf,
			     fuse_fill_dir_t filler, off_t offset,
			     struct fuse_file_info *fi,
			     enum fuse_readdir_flags flags)
{
	const char *pp;
	struct iv_avl_tree dentries;
	struct iv_list_head *lh;
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "readdir called with [%s]\n", path);
		return -ENOENT;
	}

	if (path[1])
		pp = path + 1;
	else
		pp = ".";

	INIT_IV_AVL_TREE(&dentries, compare_dentries);

	ret = 0;
	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;
		int fd;
		DIR *dirp;

		r = iv_container_of(lh, struct repo, list);

		fd = openat(r->imagedir, pp, O_DIRECTORY | O_RDONLY);
		if (fd < 0) {
			ret = -errno;
			break;
		}

		dirp = fdopendir(fd);
		if (dirp == NULL) {
			ret = -errno;
			close(fd);
			break;
		}

		while (1) {
			struct dirent *dent;
			unsigned char d_type;
			int len;
			struct dentry *d;

			errno = 0;

			dent = readdir(dirp);
			if (dent == NULL) {
				ret = -errno;
				break;
			}

			if (find_dentry(&dentries, dent->d_name))
				continue;

			d_type = dent->d_type;
			if (d_type == DT_UNKNOWN) {
				struct stat sbuf;

				ret = fstatat(r->imagedir, dent->d_name,
					      &sbuf, 0);

				if (ret == 0 &&
				    (sbuf.st_mode & S_IFMT) == S_IFREG) {
					d_type = DT_REG;
				}
			}

			if (d_type != DT_DIR && d_type != DT_REG &&
			    d_type != DT_LNK)
				continue;

			filler(buf, dent->d_name, NULL, 0, 0);

			len = strlen(dent->d_name);

			d = alloca(sizeof(*d) + len + 1);

			memcpy(d->name, dent->d_name, len);
			d->name[len] = 0;

			iv_avl_tree_insert(&dentries, &d->an);
		}

		closedir(dirp);
	}

	return ret;
}

static int repomount_fallocate(const char *path, int mode, off_t offset,
			       off_t length, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	int ret;

	if (!(mode & FALLOC_FL_PUNCH_HOLE))
		return -EINVAL;

	if (!fh->writeable)
		return -EBADF;

	if (offset < 0)
		return -EINVAL;
	if (offset >= fh->size)
		return -ENOSPC;

	if (offset + length > fh->size)
		length = fh->size - offset;

	pthread_mutex_lock(&fh->lock);

	ret = 0;
	while (length) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		uint32_t chunk_size;
		size_t chunk_tozero;
		struct dirty_chunk *c;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		chunk_size = compute_chunk_size(fh, chunk_index);

		chunk_tozero = chunk_size - chunk_offset;
		if (chunk_tozero > length)
			chunk_tozero = length;

		c = __find_dirty_chunk(fh, chunk_index);
		if (c == NULL && chunk_tozero < fh->size_firstchunk) {
			if (chunk_tozero < chunk_size)
				c = __get_dirty_chunk(fh, chunk_index, 1);
			else
				c = __get_dirty_chunk(fh, chunk_index, 0);

			if (c == NULL) {
				ret = -EIO;
				goto out;
			}
		}

		if (c != NULL) {
			memset(c->buf + chunk_offset, 0, chunk_tozero);
		} else {
			int ret;

			if (!fh->wrote_empty_chunk) {
				c = alloca(sizeof(*c) + fh->size_firstchunk);
				c->chunk_index = chunk_index;
				c->length = fh->size_firstchunk;
				clock_gettime(CLOCK_REALTIME, &c->last_write);
				memset(c->buf, 0, fh->size_firstchunk);

				write_dirty_chunk(fh, c, fh->empty_chunk_hash);
				fh->wrote_empty_chunk = 1;
			}

			ret = xpwrite(fh->fd, fh->empty_chunk_hash, hash_size,
				      chunk_index * hash_size);
			if (ret != hash_size) {
				if (ret >= 0) {
					fprintf(stderr, "repomount_fallocate: "
							"short write\n");
				}
				abort();
			}
		}

		offset += chunk_tozero;
		length -= chunk_tozero;
	}

out:
	pthread_mutex_unlock(&fh->lock);

	return ret;
}

static struct fuse_operations repomount_oper = {
	.getattr	= repomount_getattr,
	.readlink	= repomount_readlink,
	.truncate	= repomount_truncate,
	.open		= repomount_open,
	.read		= repomount_read,
	.write		= repomount_write,
	.statfs		= repomount_statfs,
	.release	= repomount_release,
	.fsync		= repomount_fsync,
	.readdir	= repomount_readdir,
	.fallocate	= repomount_fallocate,
};

static void usage(const char *progname)
{
	fprintf(stderr,
"Usage: %s <backingdir>+ <mountpoint> [options]\n"
"\n"
"General options:\n"
"         --help            print help\n"
"    -V   --version         print version\n"
"    -h   --hash-algo=x     hash algorithm\n"
"\n", progname);
}

enum {
	KEY_HELP,
	KEY_VERSION,
};

struct repomount_param
{
	char	*hash_algo;
};

#define EFES_OPT(t, o)	{ t, offsetof(struct repomount_param, o), -1, }

static struct fuse_opt opts[] = {
	EFES_OPT("-h %s",		hash_algo),
	EFES_OPT("--hash-algo=%s",	hash_algo),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("-V",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_END,
};

static int opt_proc(void *data, const char *arg, int key,
		    struct fuse_args *outargs)
{
	if (key == FUSE_OPT_KEY_NONOPT) {
		if (reposet_add_repo(&rs, arg) < 0)
			return 1;

		return 0;
	}

	if (key == KEY_HELP) {
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		fuse_main(outargs->argc, outargs->argv, &repomount_oper, NULL);
		exit(EXIT_FAILURE);
	}

	if (key == KEY_VERSION) {
		fprintf(stderr, "repomount version: %s\n", PACKAGE_VERSION);
		fuse_opt_add_arg(outargs, "--version");
		fuse_main(outargs->argc, outargs->argv, &repomount_oper, NULL);
		exit(EXIT_SUCCESS);
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct repomount_param param;
	int ret;

	reposet_init(&rs);

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	memset(&param, 0, sizeof(param));

	if (fuse_opt_parse(&args, &param, opts, opt_proc) < 0)
		return 1;

	if (param.hash_algo != NULL) {
		hash_algo = gcry_md_map_name(param.hash_algo);
		if (hash_algo == 0) {
			fprintf(stderr, "unknown hash algorithm "
					"name: %s\n", param.hash_algo);
			return 1;
		}
	}

	hash_size = gcry_md_get_algo_dlen(hash_algo);
	reposet_set_hash_size(&rs, hash_size);

	if (iv_list_empty(&rs.repos)) {
		fprintf(stderr, "missing repositories\n");
		fprintf(stderr, "see '%s --help' for usage\n", argv[0]);
		return 1;
	}

	ret = fuse_main(args.argc, args.argv, &repomount_oper, NULL);

	fuse_opt_free_args(&args);
	if (param.hash_algo != NULL)
		free(param.hash_algo);

	return ret;
}
