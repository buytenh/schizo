/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2020, 2022 Lennert Buytenhek
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

#define MAX_CHUNKS		512

struct repomount_file_info {
	int			fd;
	uint64_t		numchunks;
	uint64_t		size;
	uint32_t		size_firstchunk;

	int			writeable;

	pthread_mutex_t		lock;
	struct iv_avl_tree	chunks;
	uint64_t		num_chunks;
	struct iv_list_head	lru;

	bool			wrote_empty_chunk;
	uint8_t			empty_chunk_hash[];
};

struct chunk {
	/* Under file lock.  */
	struct iv_avl_node	an;
	struct iv_list_head	list_lru;

	/* Immutable after creation.  */
	uint64_t		chunk_index;
	uint32_t		length;

	/* Locally protected state.  */
	pthread_mutex_t		lock;
	int			state;
	int			num_waiters;
	pthread_cond_t		state_io_complete;
	struct timespec		last_write;

	uint8_t			buf[];
};

enum {
	STATE_READING = 1,
	STATE_READ_ERROR,
	STATE_CLEAN,
	STATE_DIRTY,
	STATE_WRITEOUT,
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static struct reposet rs;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static int repomount_getattr(const char *path, struct stat *buf,
			     struct fuse_file_info *fi)
{
	int i;
	int fd;
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "getattr called with [%s]\n", path);
		return -ENOENT;
	}

	if (path[1] == 0) {
		for (i = 0; i < rs.num_repos; i++) {
			struct repo *r;

			r = rs.repos[i];

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
	int i;

	if (path[0] != '/') {
		fprintf(stderr, "readlink called with [%s]\n", path);
		return -ENOENT;
	}

	for (i = 0; i < rs.num_repos; i++) {
		struct repo *r;
		int ret;

		r = rs.repos[i];

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

static void __write_chunk(struct repomount_file_info *fh,
			  struct chunk *c, uint8_t *hash)
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
		fprintf(stderr, "__write_chunk: no copies written\n");
		abort();
	}
}

static void __check_write_empty_chunk(struct repomount_file_info *fh)
{
	if (!fh->wrote_empty_chunk) {
		struct chunk *c;

		c = alloca(sizeof(*c) + fh->size_firstchunk);
		c->length = fh->size_firstchunk;
		clock_gettime(CLOCK_REALTIME, &c->last_write);
		memset(c->buf, 0, fh->size_firstchunk);

		__write_chunk(fh, c, fh->empty_chunk_hash);
		fh->wrote_empty_chunk = true;
	}
}

static int repomount_truncate(const char *path, off_t length,
			      struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	uint64_t fromchunks;
	uint64_t tochunks;
	uint64_t i;

	pthread_mutex_lock(&fh->lock);

	if ((fh->size % fh->size_firstchunk) != 0) {
		pthread_mutex_unlock(&fh->lock);
		return -EINVAL;
	}
	fromchunks = fh->size / fh->size_firstchunk;

	if ((length % fh->size_firstchunk) != 0) {
		pthread_mutex_unlock(&fh->lock);
		return -EINVAL;
	}
	tochunks = length / fh->size_firstchunk;

	if (tochunks < fromchunks) {
		pthread_mutex_unlock(&fh->lock);
		return -EINVAL;
	}

	if (tochunks == fromchunks) {
		pthread_mutex_unlock(&fh->lock);
		return 0;
	}

	__check_write_empty_chunk(fh);

	for (i = fromchunks; i < tochunks; i++) {
		int ret;

		ret = xpwrite(fh->fd, fh->empty_chunk_hash, hash_size,
			      i * hash_size);
		if (ret != hash_size) {
			if (ret >= 0) {
				fprintf(stderr, "repomount_truncate: "
						"short write\n");
			}
			abort();
		}
	}

	fh->numchunks = tochunks;
	fh->size = length;

	pthread_mutex_unlock(&fh->lock);

	return 0;
}

static int compare_chunks(const struct iv_avl_node *_a,
			  const struct iv_avl_node *_b)
{
	const struct chunk *a;
	const struct chunk *b;

	a = iv_container_of(_a, struct chunk, an);
	b = iv_container_of(_b, struct chunk, an);

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
	INIT_IV_AVL_TREE(&fh->chunks, compare_chunks);
	fh->num_chunks = 0;
	INIT_IV_LIST_HEAD(&fh->lru);

	fh->wrote_empty_chunk = false;

	fi->fh = (int64_t)fh;

	return 0;
}

static struct chunk *__find_chunk(struct repomount_file_info *fh,
				  uint64_t chunk_index)
{
	struct iv_avl_node *an;

	an = fh->chunks.root;
	while (an != NULL) {
		struct chunk *c;

		c = iv_container_of(an, struct chunk, an);
		if (chunk_index == c->chunk_index)
			return c;

		if (chunk_index < c->chunk_index)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static void write_chunk(struct repomount_file_info *fh, struct chunk *c)
{
	uint8_t hash[hash_size];
	int ret;

	__write_chunk(fh, c, hash);

	ret = xpwrite(fh->fd, hash, hash_size, c->chunk_index * hash_size);
	if (ret != hash_size) {
		if (ret >= 0)
			fprintf(stderr, "write_chunk: short write\n");
		abort();
	}
}

static bool __check_evict_chunks(struct repomount_file_info *fh)
{
	bool fh_lock_dropped;
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	fh_lock_dropped = false;

again:
	iv_list_for_each_safe (lh, lh2, &fh->lru) {
		struct chunk *c;

		if (fh->num_chunks < MAX_CHUNKS)
			break;

		c = iv_container_of(lh, struct chunk, list_lru);

		pthread_mutex_lock(&c->lock);

		if (c->state == STATE_DIRTY) {
			fh_lock_dropped = true;

			pthread_mutex_unlock(&fh->lock);

			c->state = STATE_WRITEOUT;
			pthread_mutex_unlock(&c->lock);

			write_chunk(fh, c);

			pthread_mutex_lock(&c->lock);
			c->state = STATE_CLEAN;
			if (c->num_waiters)
				pthread_cond_broadcast(&c->state_io_complete);
			pthread_mutex_unlock(&c->lock);

			pthread_mutex_lock(&fh->lock);
			goto again;
		}

		if ((c->state == STATE_READ_ERROR ||
		     c->state == STATE_CLEAN) && c->num_waiters == 0) {
			iv_avl_tree_delete(&fh->chunks, &c->an);
			pthread_mutex_unlock(&c->lock);
			pthread_mutex_destroy(&c->lock);
			fh->num_chunks--;
			iv_list_del(&c->list_lru);

			free(c);
		} else {
			pthread_mutex_unlock(&c->lock);
		}
	}

	if (fh->num_chunks >= MAX_CHUNKS) {
		fprintf(stderr, "__check_evict_chunks: not enough "
				"chunks freed!\n");
	}

	return fh_lock_dropped;
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

static int __read_chunk(struct repomount_file_info *fh, struct chunk *c)
{
	uint8_t hash[hash_size];
	int ret;

	ret = xpread(fh->fd, hash, hash_size, c->chunk_index * hash_size);
	if (ret != hash_size)
		return -1;

	if (reposet_read_chunk(&rs, hash, c->buf, c->length) < 0)
		return -1;

	if (c->length < fh->size_firstchunk) {
		memset(c->buf + c->length, 0,
		       fh->size_firstchunk - c->length);
	}

	return 0;
}

static struct chunk *__create_chunk(struct repomount_file_info *fh,
				    uint64_t chunk_index, bool must_read_data)
{
	struct chunk *c;
	int ret;

	c = malloc(sizeof(*c) + fh->size_firstchunk);
	if (c == NULL) {
		fprintf(stderr, "__create_chunk: out of memory\n");
		pthread_mutex_unlock(&fh->lock);
		return NULL;
	}

	c->chunk_index = chunk_index;
	c->length = compute_chunk_size(fh, chunk_index);

	pthread_mutex_init(&c->lock, NULL);
	c->num_waiters = 0;
	pthread_cond_init(&c->state_io_complete, NULL);
	c->last_write = (struct timespec) { 0, 0, };

	if (iv_avl_tree_insert(&fh->chunks, &c->an) < 0) {
		fprintf(stderr, "%d: chunk %" PRId64 " already exists\n",
			gettid(), chunk_index);
		abort();
	}
	fh->num_chunks++;
	iv_list_add_tail(&c->list_lru, &fh->lru);

	if (must_read_data) {
		c->state = STATE_READING;
		pthread_mutex_unlock(&fh->lock);

		ret = __read_chunk(fh, c);

		pthread_mutex_lock(&c->lock);

		if (ret < 0)
			c->state = STATE_READ_ERROR;
		else
			c->state = STATE_CLEAN;

		if (c->num_waiters)
			pthread_cond_broadcast(&c->state_io_complete);
	} else {
		pthread_mutex_lock(&c->lock);
		c->state = STATE_DIRTY;
		memset(c->buf, 0, c->length);

		pthread_mutex_unlock(&fh->lock);
	}

	return c;
}

static struct chunk *
__get_locked_chunk_wait_readable(struct repomount_file_info *fh,
				 uint64_t chunk_index, bool must_read_data)
{
	struct chunk *c;

again:
	c = __find_chunk(fh, chunk_index);

	if (c != NULL) {
		iv_list_del(&c->list_lru);
		iv_list_add_tail(&c->list_lru, &fh->lru);

		pthread_mutex_lock(&c->lock);
		pthread_mutex_unlock(&fh->lock);

		while (c->state == STATE_READING) {
			c->num_waiters++;
			pthread_cond_wait(&c->state_io_complete, &c->lock);
			c->num_waiters--;
		}
	} else {
		if (__check_evict_chunks(fh))
			goto again;

		c = __create_chunk(fh, chunk_index, must_read_data);
	}

	return c;
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

	processed = 0;
	while (size) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		size_t toread;
		struct chunk *c;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		toread = fh->size_firstchunk - chunk_offset;
		if (toread > size)
			toread = size;

		pthread_mutex_lock(&fh->lock);

		c = __get_locked_chunk_wait_readable(fh, chunk_index, true);
		if (c == NULL)
			goto eio;

		if (c->state == STATE_READ_ERROR) {
			pthread_mutex_unlock(&c->lock);
			goto eio;
		}

		memcpy(buf, c->buf + chunk_offset, toread);

		pthread_mutex_unlock(&c->lock);

		buf += toread;
		size -= toread;
		offset += toread;

		processed += toread;
	}

	return processed;

eio:
	return processed ? processed : -EIO;
}

static void __wait_writeout_done(struct chunk *c)
{
	while (c->state == STATE_WRITEOUT) {
		c->num_waiters++;
		pthread_cond_wait(&c->state_io_complete, &c->lock);
		c->num_waiters--;
	}
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

	processed = 0;
	while (size) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		uint32_t chunk_size;
		bool must_read_data;
		struct chunk *c;
		size_t towrite;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		chunk_size = compute_chunk_size(fh, chunk_index);

		if (chunk_offset != 0 || size < chunk_size)
			must_read_data = true;
		else
			must_read_data = false;

		pthread_mutex_lock(&fh->lock);

		c = __get_locked_chunk_wait_readable(fh, chunk_index,
						     must_read_data);
		if (c == NULL)
			goto eio;

		if (c->state == STATE_READ_ERROR) {
			pthread_mutex_unlock(&c->lock);
			goto eio;
		}

		__wait_writeout_done(c);

		towrite = c->length - chunk_offset;
		if (towrite > size)
			towrite = size;

		if (c->state == STATE_DIRTY) {
			memcpy(c->buf + chunk_offset, buf, towrite);
		} else if (memcmp(c->buf + chunk_offset, buf, towrite)) {
			c->state = STATE_DIRTY;
			memcpy(c->buf + chunk_offset, buf, towrite);
		}

		pthread_mutex_unlock(&c->lock);

		buf += towrite;
		size -= towrite;
		offset += towrite;

		processed += towrite;
	}

	return processed;

eio:
	return processed ? processed : -EIO;
}

static int repomount_statfs(const char *path, struct statvfs *buf)
{
	int i;

	if (path[0] != '/') {
		fprintf(stderr, "statfs called with [%s]\n", path);
		return -ENOENT;
	}

	for (i = 0; i < rs.num_repos; i++) {
		struct repo *r;
		int ret;

		r = rs.repos[i];

		ret = fstatvfs(r->chunkdir, buf);
		if (ret < 0)
			continue;

		return 0;
	}

	return -EIO;
}

static int repomount_release(const char *path, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	struct iv_avl_node *an;
	struct iv_avl_node *an2;

again:
	iv_avl_tree_for_each_safe (an, an2, &fh->chunks) {
		struct chunk *c;

		c = iv_container_of(an, struct chunk, an);

		if (c->state == STATE_DIRTY) {
			write_chunk(fh, c);
			c->state = STATE_CLEAN;
		}

		if (c->state == STATE_READ_ERROR || c->state == STATE_CLEAN) {
			iv_avl_tree_delete(&fh->chunks, &c->an);
			pthread_mutex_destroy(&c->lock);
			free(c);
		} else {
			fprintf(stderr, "repomount_release: found chunk %p "
					"in state %d\n", c, c->state);
		}
	}

	if (!iv_avl_tree_empty(&fh->chunks)) {
		fprintf(stderr, "repomount_release: waiting for busy "
				"chunks to finish I/O\n");

		iv_avl_tree_for_each (an, &fh->chunks) {
			struct chunk *c;

			c = iv_container_of(an, struct chunk, an);

			while (c->state == STATE_READING ||
			       c->state == STATE_WRITEOUT) {
				fprintf(stderr, "repomount_release: waiting "
						"for chunk %p in state %d\n",
					c, c->state);

				c->num_waiters++;
				pthread_cond_wait(&c->state_io_complete,
						  &c->lock);
				c->num_waiters--;
			}
		}

		goto again;
	}

	close(fh->fd);
	free(fh);

	return 0;
}

static int repomount_fsync(const char *path, int datasync,
			   struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;
	struct iv_avl_node *an;

	pthread_mutex_lock(&fh->lock);

	iv_avl_tree_for_each (an, &fh->chunks) {
		struct chunk *c;

		c = iv_container_of(an, struct chunk, an);

		pthread_mutex_lock(&c->lock);

		if (c->state == STATE_DIRTY) {
			write_chunk(fh, c);
			c->state = STATE_CLEAN;
		} else if (c->state == STATE_WRITEOUT) {
			__wait_writeout_done(c);
		}

		pthread_mutex_unlock(&c->lock);
	}

	pthread_mutex_unlock(&fh->lock);

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
	int i;
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
	for (i = 0; i < rs.num_repos; i++) {
		struct repo *r;
		int fd;
		DIR *dirp;

		r = rs.repos[i];

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

static ssize_t zero_chunk_from(struct repomount_file_info *fh,
			       uint64_t chunk_index, uint32_t chunk_offset,
			       off_t length)
{
	uint32_t chunk_size;
	size_t tozero;
	struct chunk *c;

	chunk_size = compute_chunk_size(fh, chunk_index);

	tozero = chunk_size - chunk_offset;
	if (tozero > length)
		tozero = length;

	pthread_mutex_lock(&fh->lock);

	c = __find_chunk(fh, chunk_index);

	if (c == NULL && tozero == fh->size_firstchunk) {
		int ret;

		__check_write_empty_chunk(fh);

		ret = xpwrite(fh->fd, fh->empty_chunk_hash, hash_size,
			      chunk_index * hash_size);
		if (ret != hash_size) {
			if (ret >= 0) {
				fprintf(stderr, "zero_chunk_from: "
						"short write\n");
			}
			abort();
		}

		pthread_mutex_unlock(&fh->lock);
	} else {
		if (c != NULL) {
			iv_list_del(&c->list_lru);
			iv_list_add_tail(&c->list_lru, &fh->lru);

			pthread_mutex_lock(&c->lock);
			pthread_mutex_unlock(&fh->lock);

			while (c->state == STATE_READING) {
				c->num_waiters++;
				pthread_cond_wait(&c->state_io_complete,
						  &c->lock);
				c->num_waiters--;
			}
		} else {
			c = __get_locked_chunk_wait_readable(fh,
						chunk_index, true);
			if (c == NULL)
				return -EIO;
		}

		if (c->state == STATE_READ_ERROR) {
			pthread_mutex_unlock(&c->lock);
			return -EIO;
		}

		__wait_writeout_done(c);

		c->state = STATE_DIRTY;
		memset(c->buf + chunk_offset, 0, tozero);
		pthread_mutex_unlock(&c->lock);
	}

	return tozero;
}

static int repomount_fallocate(const char *path, int mode, off_t offset,
			       off_t length, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;

	if (!(mode & FALLOC_FL_PUNCH_HOLE) &&
	    !(mode & FALLOC_FL_ZERO_RANGE))
		return -EINVAL;

	if (!fh->writeable)
		return -EBADF;

	if (offset < 0)
		return -EINVAL;
	if (offset >= fh->size)
		return -ENOSPC;

	if (offset + length > fh->size)
		length = fh->size - offset;

	while (length) {
		uint64_t chunk_index;
		uint32_t chunk_offset;
		ssize_t ret;

		chunk_index = offset / fh->size_firstchunk;
		chunk_offset = offset % fh->size_firstchunk;

		ret = zero_chunk_from(fh, chunk_index, chunk_offset, length);
		if (ret < 0)
			return ret;

		offset += ret;
		length -= ret;
	}

	return 0;
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

	reposet_set_hash_algo(&rs, hash_algo);

	hash_size = gcry_md_get_algo_dlen(hash_algo);
	reposet_set_hash_size(&rs, hash_size);

	if (rs.num_repos == 0) {
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
