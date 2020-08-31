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
#include <unistd.h>
#include "reposet.h"
#include "rw.h"

struct repomount_file_info {
	int		fd;
	uint64_t	numchunks;
	uint64_t	size;
	uint32_t	size_firstchunk;
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static struct reposet rs;
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

	fd = reposet_open_image(&rs, path + 1);
	if (fd < 0)
		return fd;

	ret = reposet_stat_image(&rs, fd, NULL, buf);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	close(fd);

	buf->st_mode &= ~0222;

	return 0;
}

static int repomount_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	struct image_info info;
	struct repomount_file_info *fh;
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "open called with [%s]\n", path);
		return -ENOENT;
	}

	fd = reposet_open_image(&rs, path + 1);
	if (fd < 0)
		return fd;

	if ((fi->flags & O_ACCMODE) != O_RDONLY) {
		close(fd);
		return -EACCES;
	}

	ret = reposet_stat_image(&rs, fd, &info, NULL);
	if (ret < 0)
		return ret;

	fh = malloc(sizeof(*fh));
	if (fh == NULL) {
		close(fd);
		return -ENOMEM;
	}

	fh->fd = fd;
	fh->numchunks = info.numchunks;
	fh->size = info.size;
	fh->size_firstchunk = info.size_firstchunk;

	fi->fh = (int64_t)fh;

	return 0;
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

	if (size > INT_MAX)
		size = INT_MAX;
	if (offset + size > fh->size)
		size = fh->size - offset;

	processed = 0;
	while (size) {
		uint8_t hash[hash_size];
		int ret;
		int fd;
		off_t offset_chunk;
		size_t toread_chunk;

		ret = xpread(fh->fd, hash, hash_size,
			     (offset / fh->size_firstchunk) * hash_size);
		if (ret != hash_size)
			return processed ? processed : -EIO;

		fd = reposet_open_chunk(&rs, hash);
		if (fd < 0) {
			if (ret < 0)
				perror("openat");
			return processed ? processed : -EIO;
		}

		offset_chunk = offset % fh->size_firstchunk;

		toread_chunk = fh->size_firstchunk - offset_chunk;
		if (toread_chunk > size)
			toread_chunk = size;

		ret = xpread(fd, buf, toread_chunk, offset_chunk);
		if (ret <= 0) {
			close(fd);
			return processed ? processed : -EIO;
		}

		close(fd);

		buf += ret;
		size -= ret;
		offset += ret;

		processed += ret;
	}

	return processed;
}

static int repomount_statfs(const char *path, struct statvfs *buf)
{
	struct iv_list_head *lh;

	if (strcmp(path, "/")) {
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

static int repomount_release(const char *path, struct fuse_file_info *fi)
{
	struct repomount_file_info *fh = (void *)fi->fh;

	close(fh->fd);
	free(fh);

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
	struct iv_avl_tree dentries;
	struct iv_list_head *lh;
	int ret;

	if (strcmp(path, "/") != 0) {
		fprintf(stderr, "readdir called with [%s]\n", path);
		return 0;
	}

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

	INIT_IV_AVL_TREE(&dentries, compare_dentries);

	ret = 0;
	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;
		int fd;
		DIR *dirp;

		r = iv_container_of(lh, struct repo, list);

		fd = openat(r->imagedir, ".", O_DIRECTORY | O_RDONLY);
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

			if (d_type != DT_REG)
				continue;

			filler(buf, dent->d_name, NULL, 0, 0);

			len = strlen(dent->d_name);

			d = malloc(sizeof(*d) + len + 1);
			if (d == NULL) {
				ret = -ENOMEM;
				break;
			}

			memcpy(d->name, dent->d_name, len);
			d->name[len] = 0;

			iv_avl_tree_insert(&dentries, &d->an);
		}

		closedir(dirp);
	}

	return ret;
}

static struct fuse_operations repomount_oper = {
	.getattr	= repomount_getattr,
	.open		= repomount_open,
	.read		= repomount_read,
	.statfs		= repomount_statfs,
	.release	= repomount_release,
	.readdir	= repomount_readdir,
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
	int hash_algo;
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

	hash_algo = GCRY_MD_SHA512;
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
