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
#include <iv_avl.h>
#include <iv_list.h>
#include <limits.h>
#include "base64enc.h"
#include "enumerate_chunks.h"
#include "enumerate_images.h"
#include "enumerate_image_chunks.h"
#include "reposet.h"
#include "schizo.h"

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

static int report_missing_chunks(void)
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

	return missing ? 1 : 0;
}

int fsck(int argc, char *argv[])
{
	int i;

	if (argc)
		return -1;

	num_images = enumerate_images(&images, &rs);

	enumerate_image_chunks(chunks, hash_size, num_images, &images, 128);

	num = 0;

	for (i = 0; i < rs.num_repos; i++) {
		struct repo *r;

		r = rs.repos[i];

		enumerate_chunks(r, hash_size,
				 sizeof(struct fsck_thread_state),
				 128, fsck_thread_init, NULL, got_chunk,
				 fsck_thread_deinit);
	}

	return report_missing_chunks();
}
