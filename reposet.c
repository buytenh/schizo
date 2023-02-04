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
#include <gcrypt.h>
#include <limits.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include "base64enc.h"
#include "reposet.h"
#include "rw.h"

void reposet_init(struct reposet *rs)
{
	rs->hash_algo = 0;
	rs->hash_size = 0;

	rs->num_repos = 0;

	rs->repo_read = 0;
}

void reposet_set_hash_algo(struct reposet *rs, int hash_algo)
{
	rs->hash_algo = hash_algo;
}

void reposet_set_hash_size(struct reposet *rs, int hash_size)
{
	rs->hash_size = hash_size;
}

int reposet_add_repo(struct reposet *rs, const char *path)
{
	int repodir;
	int chunkdir;
	int corruptdir;
	int deldir;
	int imagedir;
	struct repo *r;

	if (rs->num_repos == MAX_REPOS) {
		fprintf(stderr, "reposet_add_repo: repository limit reached\n");
		return -1;
	}

	repodir = open(path, O_DIRECTORY | O_PATH);
	if (repodir < 0)
		return -1;

	chunkdir = openat(repodir, "chunks", O_DIRECTORY | O_PATH);
	if (chunkdir < 0) {
		close(repodir);
		return -1;
	}

	corruptdir = openat(repodir, "corrupt", O_DIRECTORY);

	deldir = openat(repodir, "deleted", O_DIRECTORY);

	imagedir = openat(repodir, "images", O_DIRECTORY);
	if (imagedir < 0) {
		if (deldir != -1)
			close(deldir);
		if (corruptdir != -1)
			close(corruptdir);
		close(chunkdir);
		close(repodir);
		return -1;
	}

	r = malloc(sizeof(*r));
	if (r == NULL) {
		close(imagedir);
		if (deldir != -1)
			close(deldir);
		if (corruptdir != -1)
			close(corruptdir);
		close(chunkdir);
		return -1;
	}

	r->path = strdup(path);
	r->repodir = repodir;
	r->chunkdir = chunkdir;
	r->corruptdir = corruptdir;
	r->deldir = deldir;
	r->imagedir = imagedir;
	r->tmpdir = -1;

	rs->repos[rs->num_repos++] = r;

	return 0;
}

int reposet_open_image(const struct reposet *rs, const char *image, mode_t mode)
{
	int i;

	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;
		int fd;

		r = rs->repos[i];

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
	int i;

	ret = xpread(imagefd, hash, rs->hash_size, chunk_index * rs->hash_size);
	if (ret != rs->hash_size)
		return -1;

	snprintf(name, sizeof(name), "%.2x/%.2x/", hash[0], hash[1]);
	base64enc(name + 6, hash, rs->hash_size);

	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;
		struct stat buf;

		r = rs->repos[i];

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

static void print_hash(const uint8_t *hash, int hash_size)
{
	char h[2 * hash_size + 1];
	int i;

	for (i = 0; i < hash_size; i++)
		sprintf(&h[2 * i], "%.2x", hash[i]);

	fwrite(h, 1, 2 * hash_size, stderr);
}

static int read_chunk(const struct reposet *rs, struct repo *r, int fd,
		      const uint8_t *hash, uint8_t *data, int datalen)
{
	ssize_t ret;
	uint8_t computed_hash[rs->hash_size];

	ret = xpread(fd, data, datalen, 0);
	if (ret != datalen) {
		fprintf(stderr, "reposet_read_chunk: ");
		if (ret < 0) {
			fprintf(stderr, "error %s while reading chunk ",
				strerror(errno));
		} else {
			fprintf(stderr, "short read of %jd (expected %jd) "
					"while reading chunk ",
				(intmax_t)ret, (intmax_t)datalen);
		}

		print_hash(hash, rs->hash_size);
		fprintf(stderr, " from repo %s\n", r->path);

		return -1;
	}

	gcry_md_hash_buffer(rs->hash_algo, computed_hash, data, datalen);

	if (memcmp(hash, computed_hash, rs->hash_size)) {
		fprintf(stderr, "reposet_read_chunk: hash mismatch for chunk ");
		print_hash(hash, rs->hash_size);
		fprintf(stderr, " (got: ");
		print_hash(computed_hash, rs->hash_size);
		fprintf(stderr, " in repo %s\n", r->path);

		return -1;
	}

	return 0;
}

int reposet_read_chunk(struct reposet *rs, const uint8_t *hash,
		       uint8_t *data, int datalen)
{
	char name[6 + B64SIZE(rs->hash_size) + 1];
	unsigned int first;
	int i;

	snprintf(name, sizeof(name), "%.2x/%.2x/", hash[0], hash[1]);
	base64enc(name + 6, hash, rs->hash_size);

	first = __atomic_fetch_add(&rs->repo_read, 1, __ATOMIC_RELAXED);
	if (rs->num_repos)
		first %= rs->num_repos;

	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;
		int fd;
		int ret;

		r = rs->repos[(first + i) % rs->num_repos];

		fd = openat(r->chunkdir, name, O_RDONLY);
		if (fd < 0) {
			if (errno != ENOENT)
				perror("openat");
			continue;
		}

		ret = read_chunk(rs, r, fd, hash, data, datalen);
		close(fd);

		if (ret == 0)
			return 0;
	}

	fprintf(stderr, "reposet_read_chunk: can't find good copy of chunk ");
	print_hash(hash, rs->hash_size);
	fprintf(stderr, "\n");

	return -1;
}

int reposet_undelete_chunk(const struct reposet *rs, const uint8_t *hash)
{
	char name[B64SIZE(rs->hash_size) + 1];
	char dirname[6 + B64SIZE(rs->hash_size) + 1];
	int undeleted;
	int i;

	base64enc(name, hash, rs->hash_size);

	snprintf(dirname, sizeof(dirname), "%.2x/%.2x", hash[0], hash[1]);
	dirname[5] = '/';
	memcpy(dirname + 6, name, B64SIZE(rs->hash_size));
	dirname[6 + B64SIZE(rs->hash_size)] = 0;

	undeleted = 0;
	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;

		r = rs->repos[i];

		if (r->deldir != -1) {
			int ret;

			ret = renameat2(r->deldir, name, r->chunkdir, dirname,
					RENAME_NOREPLACE);
			if (ret == 0)
				undeleted++;
		}
	}

	return undeleted;
}

static int repo_write_file_tmpfile(struct repo *r, int dirfd,
				   const char *name,
				   const uint8_t *data, int datalen,
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

	if (xwrite(fd, data, datalen) != datalen) {
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
				    const uint8_t *data, int datalen,
				    const struct timespec *times)
{
	int fd;
	int ret;

	fd = openat(r->tmpdir, name, O_TRUNC | O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("openat");
		return 0;
	}

	if (xwrite(fd, data, datalen) != datalen) {
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
			   const uint8_t *data, int datalen,
			   const struct timespec *times)
{
	int ret;

	ret = -1;

	if (r->tmpdir == -1) {
		ret = repo_write_file_tmpfile(r, dirfd, name,
					      data, datalen, times);
	}

	if (ret < 0) {
		ret = 0;
		if (use_tmpdir(r)) {
			ret = repo_write_file_fallback(r, dirfd, name,
						       data, datalen, times);
		}
	}

	return ret;
}

static int repo_write_image(struct repo *r, const char *image,
			    const uint8_t *hashes, uint64_t bytes,
			    const struct timespec *times)
{
	return repo_write_file(r, r->imagedir, image, hashes, bytes, times);
}

int reposet_write_image(const struct reposet *rs, const char *image,
			const uint8_t *hashes, uint64_t num_chunks,
			const struct timespec *times)
{
	uint64_t bytes;
	int copies;
	int i;

	bytes = num_chunks * rs->hash_size;

	copies = 0;
	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;

		r = rs->repos[i];

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

int reposet_write_chunk(const struct reposet *rs, const uint8_t *hash,
			const uint8_t *data, int datalen,
			const struct timespec *times)
{
	char dirname[16];
	char name[B64SIZE(rs->hash_size) + 1];
	int copies;
	int i;

	snprintf(dirname, sizeof(dirname), "%.2x/%.2x", hash[0], hash[1]);
	base64enc(name, hash, rs->hash_size);

	copies = 0;
	for (i = 0; i < rs->num_repos; i++) {
		struct repo *r;
		int dirfd;
		struct stat chunkstat;

		r = rs->repos[i];

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
		} else if (repo_write_file(r, dirfd, name,
			   data, datalen, times)) {
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
