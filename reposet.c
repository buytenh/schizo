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

	imagedir = openat(repodir, "images", O_DIRECTORY);
	if (imagedir < 0) {
		close(chunkdir);
		close(repodir);
		return -1;
	}

	close(repodir);

	r = malloc(sizeof(*r));
	if (r == NULL) {
		close(imagedir);
		close(chunkdir);
		return -1;
	}

	iv_list_add_tail(&r->list, &rs->repos);
	r->path = strdup(path);
	r->chunkdir = chunkdir;
	r->imagedir = imagedir;

	return 0;
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
		int fd;
		int ret;
		char path[128];

		r = iv_container_of(lh, struct repo, list);

		if (faccessat(r->imagedir, image, F_OK, 0) == 0)
			continue;
		if (errno != ENOENT)
			continue;

		fd = openat(r->imagedir, ".", O_RDWR | O_TMPFILE, 0666);
		if (fd < 0) {
			perror("openat");
			continue;
		}

		if (xwrite(fd, hashes, bytes) != bytes) {
			close(fd);
			continue;
		}

		if (futimens(fd, times) < 0) {
			perror("futimens");
			close(fd);
			continue;
		}

		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

		ret = linkat(AT_FDCWD, path, r->imagedir, image,
			     AT_SYMLINK_FOLLOW);
		if (ret < 0) {
			perror("linkat");
			close(fd);
			continue;
		}

		close(fd);

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
			       int (*fillcb)(int fd),
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
		} else {
			int fd;
			int ret;
			char path[128];

			fd = openat(dirfd, ".", O_RDWR | O_TMPFILE, 0666);
			if (fd < 0) {
				perror("openat");
				close(dirfd);
				continue;
			}

			if (fillcb(fd) < 0) {
				close(fd);
				close(dirfd);
				continue;
			}

			if (futimens(fd, times) < 0) {
				perror("futimens");
				close(fd);
				close(dirfd);
				continue;
			}

			snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

			ret = linkat(AT_FDCWD, path, dirfd, name,
				     AT_SYMLINK_FOLLOW);
			if (ret < 0) {
				perror("linkat");
				close(fd);
				close(dirfd);
				continue;
			}

			close(fd);
		}

		close(dirfd);

		copies++;
	}

	if (copies == 0) {
		fprintf(stderr, "reposet_write_chunk: no copies of "
				"chunk were written\n");
	}

	return copies;
}

int reposet_write_chunk_fromfd(const struct reposet *rs, const uint8_t *hash,
			       int srcfd, uint64_t off, int datalen,
			       const struct timespec *times)
{
	int fillcb(int fd)
	{
		struct file_clone_range arg;
		int offset;

		arg.src_fd = srcfd;
		arg.src_offset = off;
		arg.src_length = datalen;
		arg.dest_offset = 0;
		if (ioctl(fd, FICLONERANGE, &arg) == 0)
			return 0;

		if (errno != EINVAL && errno != EOPNOTSUPP && errno != EXDEV) {
			perror("ioctl(FICLONERANGE)");
			return -1;
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
