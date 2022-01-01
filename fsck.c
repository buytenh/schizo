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
#include <getopt.h>
#include <iv_avl.h>
#include <iv_list.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include "base64enc.h"
#include "enumerate_chunks.h"
#include "enumerate_images.h"
#include "enumerate_image_chunks.h"
#include "reposet.h"
#include "threads.h"

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static struct reposet rs;

static int num_images;
static struct iv_avl_tree images;
static struct iv_avl_tree chunks[65536];

static uint64_t num;

struct fsck_thread_state {
	uint64_t	num;
};

static void fsck_thread_init(void *_fts)
{
	struct fsck_thread_state *fts = _fts;

	fts->num = 0;
}

static void got_chunk(void *_fts, int section, const char *dir, int dirfd,
		      const char *name, const uint8_t *hash)
{
	struct fsck_thread_state *fts = _fts;
	struct chunk *c;

	c = find_chunk(&chunks[section], hash, hash_size);
	if (c != NULL) {
		iv_avl_tree_delete(&chunks[section], &c->an);
		free(c);

		fts->num++;
	}
}

static void fsck_thread_deinit(void *_fts)
{
	struct fsck_thread_state *fts = _fts;

	num += fts->num;
}

static void scan_chunks(void)
{
	struct iv_list_head *lh;

	num = 0;
	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);
		enumerate_chunks(r, hash_size,
				 sizeof(struct fsck_thread_state),
				 fsck_thread_init, got_chunk,
				 fsck_thread_deinit);
	}
}

static struct image *find_image(int index)
{
	struct iv_avl_node *an;

	an = images.root;
	while (an != NULL) {
		struct image *im;

		im = iv_container_of(an, struct image, an);
		if (index == im->index)
			return im;

		if (index < im->index)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int missing_chunk(struct chunk *c)
{
	char name[B64SIZE(hash_size) + 1];
	uint8_t *bm;
	int i;

	base64enc(name, c->data, hash_size);

	if (reposet_undelete_chunk(&rs, c->data)) {
		fprintf(stderr, "undeleted chunk %s\n", name);
		return 0;
	}

	fprintf(stderr, "can't find chunk %s\n", name);

	bm = c->data + hash_size;
	for (i = 0; i < num_images; i++) {
		if (bm[i / CHAR_BIT] & 1 << (i % CHAR_BIT))
			find_image(i)->missing_chunks++;
	}

	return 1;
}

static void report_missing_chunks(void)
{
	uint64_t missing;
	int i;
	struct iv_avl_node *an;

	missing = 0;
	for (i = 0; i < 65536; i++) {
		iv_avl_tree_for_each (an, &chunks[i]) {
			struct chunk *c;

			c = iv_container_of(an, struct chunk, an);
			missing += missing_chunk(c);
		}
	}

	printf("scanned %" PRId64 " chunks", num);
	if (missing)
		printf(", %" PRId64 " missing", missing);
	printf("\n");

	iv_avl_tree_for_each (an, &images) {
		struct image *im;

		im = iv_container_of(an, struct image, an);
		if (im->missing_chunks) {
			fprintf(stderr, "%s %s: %" PRId64 " missing chunk(s)\n",
				im->r->path, im->path, im->missing_chunks);
		}
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

	scan_chunks();

	report_missing_chunks();

	return 0;
}
