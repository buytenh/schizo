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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "base64enc.h"
#include "reposet.h"
#include "rw.h"

void reposet_init(struct reposet *rs)
{
	INIT_IV_LIST_HEAD(&rs->repos);
	rs->hash_size = 0;
}

void reposet_set_hash_size(struct reposet *rs, int hash_size)
{
	rs->hash_size = hash_size;
}

int reposet_add_repo(struct reposet *rs, const char *path)
{
	int repodir;
	int chunkdir;
	int deldir;
	int imagedir;
	struct repo *r;

	repodir = open(path, O_DIRECTORY | O_PATH);
	if (repodir < 0)
		return -1;

	chunkdir = openat(repodir, "chunks", O_DIRECTORY | O_PATH);
	if (chunkdir < 0) {
		close(repodir);
		return -1;
	}

	deldir = openat(repodir, "deleted", O_DIRECTORY);

	imagedir = openat(repodir, "images", O_DIRECTORY);
	if (imagedir < 0) {
		if (deldir != -1)
			close(deldir);
		close(chunkdir);
		close(repodir);
		return -1;
	}

	r = malloc(sizeof(*r));
	if (r == NULL) {
		close(imagedir);
		if (deldir != -1)
			close(deldir);
		close(chunkdir);
		return -1;
	}

	iv_list_add_tail(&r->list, &rs->repos);
	r->path = strdup(path);
	r->repodir = repodir;
	r->chunkdir = chunkdir;
	r->deldir = deldir;
	r->imagedir = imagedir;
	r->tmpdir = -1;
	r->clone_failed = 0;

	return 0;
}

int reposet_open_image(const struct reposet *rs, const char *image, mode_t mode)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;
		int fd;

		r = iv_container_of(lh, struct repo, list);

		fd = openat(r->imagedir, image, mode);

		if (fd < 0 && errno == ELOOP)
			fd = openat(r->imagedir, image, mode | O_PATH);

		if (fd < 0) {
			if (errno != ENOENT)
				perror("openat");
			continue;
		}

		return fd;
	}

	return -ENOENT;
}

static int
chunk_size(const struct reposet *rs, int imagefd, uint64_t chunk_index)
{
	uint8_t hash[rs->hash_size];
	int ret;
	char name[6 + B64SIZE(rs->hash_size) + 1];
	struct iv_list_head *lh;

	ret = xpread(imagefd, hash, rs->hash_size, chunk_index * rs->hash_size);
	if (ret != rs->hash_size)
		return -1;

	snprintf(name, sizeof(name), "%.2x/%.2x/", hash[0], hash[1]);
	base64enc(name + 6, hash, rs->hash_size);

	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;
		struct stat buf;

		r = iv_container_of(lh, struct repo, list);

		if (fstatat(r->chunkdir, name, &buf, 0) < 0) {
			if (errno != ENOENT) {
				fprintf(stderr, "error accessing %s: %s\n",
					name, strerror(errno));
			}
			continue;
		}

		return (buf.st_size < INT_MAX) ? buf.st_size : -1;
	}

	fprintf(stderr, "can't open chunk %s\n", name);

	return -1;
}

static int stat_chunks(const struct reposet *rs, int imagefd, uint64_t size,
		       uint64_t *numchunks_p, uint64_t *size_p,
		       uint32_t *size_firstchunk_p)
{
	uint64_t numchunks;
	int ret;

	if ((size % rs->hash_size) != 0)
		return -1;

	numchunks = size / rs->hash_size;
	*numchunks_p = numchunks;

	if (numchunks == 0) {
		*size_p = 0;
		*size_firstchunk_p = 0;
		return 0;
	}

	ret = chunk_size(rs, imagefd, 0);
	if (ret < 0)
		return -1;

	*size_p = (numchunks - 1) * ret;
	*size_firstchunk_p = ret;

	if (numchunks > 1) {
		ret = chunk_size(rs, imagefd, numchunks - 1);
		if (ret < 0)
			return -1;
	}

	*size_p += ret;

	return 0;
}

int reposet_stat_image(const struct reposet *rs, int fd,
		       struct image_info *info, struct stat *buf)
{
	struct stat statbuf;

	if (fstat(fd, &statbuf) < 0) {
		perror("fstat");
		return -1;
	}

	if (buf != NULL)
		memcpy(buf, &statbuf, sizeof(*buf));

	if ((statbuf.st_mode & S_IFMT) == S_IFREG) {
		uint64_t numchunks;
		uint64_t size;
		uint32_t size_firstchunk;
		int ret;

		ret = stat_chunks(rs, fd, statbuf.st_size, &numchunks,
				  &size, &size_firstchunk);
		if (ret < 0)
			return -ENOENT;

		if (info != NULL) {
			info->numchunks = numchunks;
			info->size = size;
			info->size_firstchunk = size_firstchunk;
		}

		if (buf != NULL) {
			buf->st_size = size;
			buf->st_blocks = size >> 9;
		}
	}

	return 0;
}

int reposet_open_chunk(const struct reposet *rs, const uint8_t *hash)
{
	char name[6 + B64SIZE(rs->hash_size) + 1];
	struct iv_list_head *lh;

	snprintf(name, sizeof(name), "%.2x/%.2x/", hash[0], hash[1]);
	base64enc(name + 6, hash, rs->hash_size);

	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;
		int fd;

		r = iv_container_of(lh, struct repo, list);

		fd = openat(r->chunkdir, name, O_RDONLY);
		if (fd >= 0)
			return fd;

		if (errno != ENOENT)
			perror("openat");
	}

	return -1;
}

static int repo_write_file_tmpfile(struct repo *r, int dirfd,
				   const char *name,
				   int (*fillcb)(struct repo *r, int fd),
				   const struct timespec *times)
{
	int fd;
	int ret;
	char path[128];

	fd = openat(dirfd, ".", O_RDWR | O_TMPFILE, 0666);
	if (fd < 0) {
		if (errno == EOPNOTSUPP)
			return -1;

		perror("openat");
		return 0;
	}

	if (fillcb(r, fd) < 0) {
		close(fd);
		return 0;
	}

	if (futimens(fd, times) < 0) {
		perror("futimens");
		close(fd);
		return 0;
	}

	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

	ret = linkat(AT_FDCWD, path, dirfd, name, AT_SYMLINK_FOLLOW);
	if (ret < 0 && errno != EEXIST) {
		perror("linkat");
		close(fd);
		return 0;
	}

	close(fd);

	return 1;
}

static int try_open_tmpdir(struct repo *r)
{
	int dir;

	dir = openat(r->repodir, "tmp", O_DIRECTORY);
	if (dir < 0) {
		if (errno == ENOENT) {
			int ret;

			ret = mkdirat(r->repodir, "tmp", 0777);
			if (ret < 0 && errno != EEXIST) {
				perror("mkdirat");
				return -1;
			}

			dir = openat(r->repodir, "tmp", O_DIRECTORY);
		}

		if (dir < 0) {
			perror("openat");
			return -1;
		}
	}

	r->tmpdir = dir;

	return 0;
}

static int use_tmpdir(struct repo *r)
{
	if (r->tmpdir == -1 && try_open_tmpdir(r) < 0)
		r->tmpdir = -2;

	if (r->tmpdir == -2)
		return 0;

	return 1;
}

static int repo_write_file_fallback(struct repo *r, int dirfd,
				    const char *name,
				    int (*fillcb)(struct repo *r, int fd),
				    const struct timespec *times)
{
	int fd;
	int ret;

	fd = openat(r->tmpdir, name, O_TRUNC | O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("openat");
		return 0;
	}

	if (fillcb(r, fd) < 0) {
		close(fd);
		unlinkat(r->tmpdir, name, 0);
		return 0;
	}

	if (futimens(fd, times) < 0) {
		perror("futimens");
		close(fd);
		unlinkat(r->tmpdir, name, 0);
		return 0;
	}

	close(fd);

	ret = renameat(r->tmpdir, name, dirfd, name);
	if (ret < 0) {
		perror("renameat");
		unlinkat(r->tmpdir, name, 0);
		return 0;
	}

	return 1;
}

static int repo_write_file(struct repo *r, int dirfd, const char *name,
			   int (*fillcb)(struct repo *r, int fd),
			   const struct timespec *times)
{
	int ret;

	ret = -1;

	if (r->tmpdir == -1)
		ret = repo_write_file_tmpfile(r, dirfd, name, fillcb, times);

	if (ret < 0) {
		ret = 0;
		if (use_tmpdir(r)) {
			ret = repo_write_file_fallback(r, dirfd, name,
						       fillcb, times);
		}
	}

	return ret;
}

static int repo_write_image(struct repo *r, const char *image,
			    const uint8_t *hashes, uint64_t bytes,
			    const struct timespec *times)
{
	int fillcb(struct repo *r, int fd)
	{
		if (xwrite(fd, hashes, bytes) != bytes)
			return -1;

		return 0;
	}

	return repo_write_file(r, r->imagedir, image, fillcb, times);
}

int reposet_write_image(const struct reposet *rs, const char *image,
			const uint8_t *hashes, uint64_t num_chunks,
			const struct timespec *times)
{
	uint64_t bytes;
	int copies;
	struct iv_list_head *lh;

	bytes = num_chunks * rs->hash_size;

	copies = 0;
	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);

		if (faccessat(r->imagedir, image, F_OK, 0) == 0)
			continue;
		if (errno != ENOENT)
			continue;

		if (repo_write_image(r, image, hashes, bytes, times))
			copies++;
	}

	return copies;
}

static int ts_before(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec < b->tv_sec)
		return 1;

	if (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec)
		return 1;

	return 0;
}

static int reposet_write_chunk(const struct reposet *rs, const uint8_t *hash,
			       int (*fillcb)(struct repo *r, int fd),
			       const struct timespec *times)
{
	char dirname[16];
	char name[B64SIZE(rs->hash_size) + 1];
	int copies;
	struct iv_list_head *lh;

	snprintf(dirname, sizeof(dirname), "%.2x/%.2x", hash[0], hash[1]);
	base64enc(name, hash, rs->hash_size);

	copies = 0;
	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;
		int dirfd;
		struct stat chunkstat;

		r = iv_container_of(lh, struct repo, list);

		dirfd = openat(r->chunkdir, dirname, O_DIRECTORY | O_PATH);
		if (dirfd < 0) {
			if (errno != ENOENT)
				perror("openat");
			continue;
		}

		if (fstatat(dirfd, name, &chunkstat, 0) == 0) {
			if (ts_before(&times[1], &chunkstat.st_mtim) &&
			    utimensat(dirfd, name, times, 0) < 0) {
				perror("utimensat");
				close(dirfd);
				continue;
			}

			copies++;
		} else if (repo_write_file(r, dirfd, name, fillcb, times)) {
			copies++;
		}

		close(dirfd);
	}

	if (copies == 0) {
		fprintf(stderr, "reposet_write_chunk: no copies of "
				"chunk were written\n");
	}

	return copies;
}

int reposet_write_chunk_frombuf(const struct reposet *rs, const uint8_t *hash,
				const uint8_t *data, int datalen,
				const struct timespec *times)
{
	int fillcb(struct repo *r, int fd)
	{
		if (xwrite(fd, data, datalen) != datalen)
			return -1;

		return 0;
	}

	return reposet_write_chunk(rs, hash, fillcb, times);
}

int reposet_write_chunk_fromfd(const struct reposet *rs, const uint8_t *hash,
			       int srcfd, uint64_t off, int datalen,
			       const struct timespec *times)
{
	int fillcb(struct repo *r, int fd)
	{
		struct file_clone_range arg;
		int offset;

		if (!r->clone_failed) {
			arg.src_fd = srcfd;
			arg.src_offset = off;
			arg.src_length = datalen;
			arg.dest_offset = 0;
			if (ioctl(fd, FICLONERANGE, &arg) == 0)
				return 0;

			if (errno != EINVAL && errno != EOPNOTSUPP &&
			    errno != EXDEV) {
				perror("ioctl(FICLONERANGE)");
				return -1;
			}

			r->clone_failed = 1;
		}

		offset = 0;
		while (offset < datalen) {
			loff_t off_in;
			ssize_t ret;

			off_in = off + offset;

			do {
				ret = copy_file_range(srcfd, &off_in, fd, NULL,
						      datalen - offset, 0);
			} while (ret < 0 && errno == EINTR);

			if (ret < 0) {
				perror("copy_file_range");
				return -1;
			}

			if (ret == 0) {
				fprintf(stderr, "reposet_write_chunk_fromfd: "
						"source got EOF!\n");
				return -1;
			}

			offset += ret;
		}

		return 0;
	}

	return reposet_write_chunk(rs, hash, fillcb, times);
}
