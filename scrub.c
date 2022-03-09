/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2021 Lennert Buytenhek
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
#include <fcntl.h>
#include <gcrypt.h>
#include <limits.h>
#include <string.h>
#include "enumerate_chunks.h"
#include "rw.h"
#include "schizo.h"

static struct repo *r;
static uint64_t num;
static uint64_t num_mismatch;

struct scrub_thread_state {
	int		corruptdir;
	uint8_t		*buf;
	size_t		buf_size;
	uint64_t	num;
	uint64_t	num_mismatch;
};

static void scrub_thread_init(void *_sts)
{
	struct scrub_thread_state *sts = _sts;

	sts->corruptdir = r->corruptdir;
	sts->buf = NULL;
	sts->buf_size = 0;
	sts->num = 0;
	sts->num_mismatch = 0;
}

static int try_open_corruptdir(struct scrub_thread_state *sts)
{
	int dir;

	dir = openat(r->repodir, "corrupt", O_DIRECTORY);
	if (dir < 0) {
		if (errno == ENOENT) {
			int ret;

			ret = mkdirat(r->repodir, "corrupt", 0777);
			if (ret < 0 && errno != EEXIST) {
				perror("mkdirat");
				return -1;
			}

			dir = openat(r->repodir, "corrupt", O_DIRECTORY);
		}

		if (dir < 0) {
			perror("openat");
			return -1;
		}
	}

	sts->corruptdir = dir;

	return 0;
}

static int use_corruptdir(struct scrub_thread_state *sts)
{
	if (sts->corruptdir == -1 && try_open_corruptdir(sts) < 0)
		sts->corruptdir = -2;

	if (sts->corruptdir == -2)
		return 0;

	return 1;
}

static void scrub_chunk(void *_sts, int section, const char *dir,
			int dirfd, const char *name, const uint8_t *hash)
{
	struct scrub_thread_state *sts = _sts;
	int fd;
	int corrupt;
	struct stat statbuf;
	uint8_t hash2[hash_size];

	fd = openat(dirfd, name, O_RDONLY);
	if (fd < 0) {
		perror("openat");
		return;
	}

	corrupt = 0;

	if (fstat(fd, &statbuf) < 0) {
		perror("fstat");
		goto out;
	}

	if (statbuf.st_size > SSIZE_MAX) {
		fprintf(stderr, "chunk %s/%s too big\n", dir, name);
		goto out;
	}

	if (sts->buf_size < statbuf.st_size) {
		if (sts->buf != NULL) {
			free(sts->buf);
			sts->buf = NULL;
		}

		sts->buf = malloc(statbuf.st_size);
		if (sts->buf == NULL) {
			fprintf(stderr, "out of memory scrubbing "
					"%s/%s, %zd bytes\n", dir, name,
				statbuf.st_size);
			goto out;
		}

		sts->buf_size = statbuf.st_size;
	}

	if (xpread(fd, sts->buf, statbuf.st_size, 0) != statbuf.st_size) {
		fprintf(stderr, "short read scrubbing %s/%s\n", dir, name);
		corrupt = 1;
		goto out;
	}

	sts->num++;

	gcry_md_hash_buffer(hash_algo, hash2, sts->buf, statbuf.st_size);
	if (memcmp(hash, hash2, hash_size)) {
		fprintf(stderr, "hash mismatch in %s/%s\n", dir, name);
		sts->num_mismatch++;
		corrupt = 1;
	}

out:
	if (corrupt && use_corruptdir(sts)) {
		renameat2(dirfd, name, sts->corruptdir, name,
			  RENAME_NOREPLACE);
	}

	close(fd);
}

static void scrub_thread_deinit(void *_sts)
{
	struct scrub_thread_state *sts = _sts;

	if (sts->corruptdir != -1 && sts->corruptdir != r->corruptdir)
		close(sts->corruptdir);

	num += sts->num;
	num_mismatch += sts->num_mismatch;
}

int scrub(int argc, char *argv[])
{
	struct iv_list_head *lh;

	if (argc)
		return -1;

	iv_list_for_each (lh, &rs.repos) {
		r = iv_container_of(lh, struct repo, list);

		num = 0;
		num_mismatch = 0;

		enumerate_chunks(r, hash_size,
				 sizeof(struct scrub_thread_state),
				 4 * sysconf(_SC_NPROCESSORS_ONLN),
				 scrub_thread_init, NULL, scrub_chunk,
				 scrub_thread_deinit);

		printf("scrubbed %" PRId64 " chunks", num);
		if (num_mismatch)
			printf(", %" PRId64 " mismatches", num_mismatch);
		printf("\n");
	}

	return 0;
}
