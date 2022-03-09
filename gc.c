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
#include <unistd.h>
#include "enumerate_chunks.h"
#include "enumerate_images.h"
#include "enumerate_image_chunks.h"
#include "schizo.h"

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

int gc(int argc, char *argv[])
{
	struct iv_list_head *lh;

	if (argc)
		return -1;

	num_images = enumerate_images(&images, &rs);

	enumerate_image_chunks(chunks, hash_size, num_images, &images, 128);

	iv_list_for_each (lh, &rs.repos) {
		r = iv_container_of(lh, struct repo, list);

		num_gcd = 0;

		enumerate_chunks(r, hash_size, sizeof(struct gc_thread_state),
				 128, gc_thread_init, NULL, check_gc_chunk,
				 gc_thread_deinit);

		if (num_gcd)
			printf("\nGCd %" PRId64 " chunks\n", num_gcd);
	}

	return 0;
}
