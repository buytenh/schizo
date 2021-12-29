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
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <unistd.h>
#include "enumerate_chunks.h"
#include "enumerate_images.h"
#include "enumerate_image_chunks.h"
#include "reposet.h"

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static struct reposet rs;

static int num_images;
static struct iv_avl_tree images;
static struct iv_avl_tree chunks[65536];

static struct repo *r;
static uint64_t num_gcd;

struct gc_thread_state {
	int		deldir;
	uint64_t	num_gcd;
};

static void gc_thread_init(void *_gts)
{
	struct gc_thread_state *gts = _gts;

	gts->deldir = r->deldir;
	gts->num_gcd = 0;
}

static int try_open_deldir(struct gc_thread_state *gts)
{
	int dir;

	dir = openat(r->repodir, "deleted", O_DIRECTORY);
	if (dir < 0) {
		if (errno == ENOENT) {
			int ret;

			ret = mkdirat(r->repodir, "deleted", 0777);
			if (ret < 0 && errno != EEXIST) {
				perror("mkdirat");
				return -1;
			}

			dir = openat(r->repodir, "deleted", O_DIRECTORY);
		}

		if (dir < 0) {
			perror("openat");
			return -1;
		}
	}

	gts->deldir = dir;

	return 0;
}

static int use_deldir(struct gc_thread_state *gts)
{
	if (gts->deldir == -1 && try_open_deldir(gts) < 0)
		gts->deldir = -2;

	if (gts->deldir == -2)
		return 0;

	return 1;
}

static void check_gc_chunk(void  *_gts, int section, const char *dir,
			   int dirfd, const char *name, const uint8_t *hash)
{
	struct gc_thread_state *gts = _gts;
	struct chunk *c;

	c = find_chunk(&chunks[section], hash, hash_size);
	if (c != NULL)
		return;

	fprintf(stderr, "chunk %s/%s not referenced\n", dir, name);

	if (use_deldir(gts)) {
		renameat2(dirfd, name, gts->deldir, name, RENAME_NOREPLACE);
		gts->num_gcd++;
	}
}

static void gc_thread_deinit(void *_gts)
{
	struct gc_thread_state *gts = _gts;

	num_gcd += gts->num_gcd;

	if (gts->deldir != -1 && gts->deldir != r->deldir)
		close(gts->deldir);
}

static void gc_repo(struct repo *_r)
{
	r = _r;
	num_gcd = 0;

	enumerate_chunks(_r, hash_size, sizeof(struct gc_thread_state),
			 gc_thread_init, check_gc_chunk, gc_thread_deinit);

	if (num_gcd)
		printf("\nGCd %" PRId64 " chunks\n", num_gcd);
}

static void gc_repos(void)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);
		gc_repo(r);
	}
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

	num_images = enumerate_images(&images, &rs);

	enumerate_image_chunks(chunks, hash_size, num_images, &images);

	gc_repos();

	return 0;
}
