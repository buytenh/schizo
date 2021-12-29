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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <limits.h>
#include "base64dec.h"
#include "enumerate_chunks.h"
#include "reposet.h"
#include "rw.h"

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static uint64_t num;
static uint64_t num_mismatch;

struct scrub_thread_state {
	uint8_t		*buf;
	size_t		buf_size;
	uint64_t	num;
	uint64_t	num_mismatch;
};

static void scrub_thread_init(void *_sts)
{
	struct scrub_thread_state *sts = _sts;

	sts->buf = NULL;
	sts->buf_size = 0;
	sts->num = 0;
	sts->num_mismatch = 0;
}

static void scrub_chunk(void *_sts, int section, const char *dir,
			int dirfd, const char *name, const uint8_t *hash)
{
	struct scrub_thread_state *sts = _sts;
	int fd;
	struct stat statbuf;
	uint8_t hash2[hash_size];

	fd = openat(dirfd, name, O_RDONLY);
	if (fd < 0) {
		perror("openat");
		return;
	}

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
		goto out;
	}

	sts->num++;

	gcry_md_hash_buffer(hash_algo, hash2, sts->buf, statbuf.st_size);
	if (memcmp(hash, hash2, hash_size)) {
		fprintf(stderr, "hash mismatch in %s/%s\n", dir, name);
		sts->num_mismatch++;
	}

out:
	close(fd);
}

static void scrub_thread_deinit(void *_sts)
{
	struct scrub_thread_state *sts = _sts;

	num += sts->num;
	num_mismatch += sts->num_mismatch;
}

static void scrub_repo(struct repo *r)
{
	num = 0;
	num_mismatch = 0;

	enumerate_chunks(r, hash_size, sizeof(struct scrub_thread_state),
			 scrub_thread_init, scrub_chunk, scrub_thread_deinit);

	printf("scrubbed %" PRId64 " chunks", num);
	if (num_mismatch)
		printf(", %" PRId64 " mismatches", num_mismatch);
	printf("\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ "repository", required_argument, 0, 'r' },
		{ 0, 0, 0, 0 },
	};
	struct reposet rs;
	struct iv_list_head *lh;

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	reposet_init(&rs);

	while (1) {
		int c;

		c = getopt_long(argc, argv, "b:h:r:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'b':
			if (sscanf(optarg, "%i", &block_size) != 1) {
				fprintf(stderr, "cannot parse block size: "
						"%s\n", optarg);
				return 1;
			}
			break;

		case 'h':
			hash_algo = gcry_md_map_name(optarg);
			if (hash_algo == 0) {
				fprintf(stderr, "unknown hash algorithm "
						"name: %s\n", optarg);
				return 1;
			}
			break;

		case 'r':
			if (reposet_add_repo(&rs, optarg) < 0) {
				fprintf(stderr, "can't add repo %s\n", optarg);
				return 1;
			}
			break;

		case '?':
			return 1;

		default:
			abort();
		}
	}

	if (argc - optind != 0) {
		fprintf(stderr, "syntax: %s [opts]\n", argv[0]);
		fprintf(stderr, " -b, --block-size=SIZE    hash block size\n");
		fprintf(stderr, " -h, --hash-algo=ALGO     hash algorithm\n");
		fprintf(stderr, " -r, --repository=DIR     repository\n");
		return 1;
	}

	if (block_size <= 0 || block_size % 4096) {
		fprintf(stderr, "block size must be a multiple of 4096\n");
		return 1;
	}

	if (iv_list_empty(&rs.repos)) {
		fprintf(stderr, "missing repositories\n");
		return 1;
	}

	hash_size = gcry_md_get_algo_dlen(hash_algo);
	reposet_set_hash_size(&rs, hash_size);

	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);
		scrub_repo(r);
	}

	return 0;
}
