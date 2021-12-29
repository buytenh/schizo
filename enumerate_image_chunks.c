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
#include <iv_avl.h>
#include <iv_list.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include "enumerate_image_chunks.h"
#include "threads.h"

struct chunk *find_chunk(struct iv_avl_tree *tree,
			 const uint8_t *hash, int hash_size)
{
	struct iv_avl_node *an;

	an = tree->root;
	while (an != NULL) {
		struct chunk *c;
		int ret;

		c = iv_container_of(an, struct chunk, an);

		ret = memcmp(hash, c->data, hash_size);
		if (ret == 0)
			return c;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}


struct state {
	struct iv_avl_tree	*chunks;
	int			hash_size;
	int			num_images;
	int			bitmap_bytes;
	pthread_mutex_t		lock_images;
	struct iv_avl_node	*an;
	pthread_mutex_t		lock_chunks[65536];
};

static struct chunk *
get_chunk(struct state *st, int tree, const uint8_t *hash)
{
	struct chunk *c;

	c = find_chunk(&st->chunks[tree], hash, st->hash_size);
	if (c != NULL)
		return c;

	c = malloc(sizeof(*c) + st->hash_size + st->bitmap_bytes);
	if (c == NULL)
		return NULL;

	memcpy(c->data, hash, st->hash_size);
	memset(c->data + st->hash_size, 0, st->bitmap_bytes);
	iv_avl_tree_insert(&st->chunks[tree], &c->an);

	return c;
}

static void *image_scan_thread(void *_st)
{
	struct state *st = _st;

	pthread_mutex_lock(&st->lock_images);

	while (st->an != NULL) {
		struct image *im;
		int fd;
		FILE *fp;

		im = iv_container_of(st->an, struct image, an);
		st->an = iv_avl_tree_next(st->an);

		printf("scanning %d/%d %s\r", im->index + 1, st->num_images,
		       im->path + 1);
		fflush(stdout);

		pthread_mutex_unlock(&st->lock_images);

		fd = openat(im->r->imagedir, im->path + 1, O_RDONLY);
		if (fd < 0) {
			perror("openat");
			pthread_mutex_lock(&st->lock_images);
			continue;
		}

		fp = fdopen(fd, "r");
		if (fp == NULL) {
			perror("fdopen");
			close(fd);
			pthread_mutex_lock(&st->lock_images);
			continue;
		}

		while (1) {
			uint8_t hash[st->hash_size];
			size_t ret;
			int section;
			struct chunk *c;

			ret = fread(hash, 1, st->hash_size, fp);
			if (ret != st->hash_size) {
				if (ferror(fp)) {
					perror("fread");
				} else if (ret) {
					fprintf(stderr, "short read %jd from "
							"%s %s\n", ret,
						im->r->path, im->path);
				}
				break;
			}

			section = (hash[0] << 8) | hash[1];

			pthread_mutex_lock(&st->lock_chunks[section]);

			c = get_chunk(st, section, hash);
			if (c == NULL) {
				fprintf(stderr, "out of memory\n");
				break;
			}

			c->data[st->hash_size + (im->index / CHAR_BIT)] |=
				1 << (im->index % CHAR_BIT);

			pthread_mutex_unlock(&st->lock_chunks[section]);
		}

		fclose(fp);

		pthread_mutex_lock(&st->lock_images);
	}

	pthread_mutex_unlock(&st->lock_images);

	return NULL;
}

void enumerate_image_chunks(struct iv_avl_tree *chunks, int hash_size,
			    int num_images, struct iv_avl_tree *images)
{
	int compare_chunks(const struct iv_avl_node *_a,
			   const struct iv_avl_node *_b)
	{
		const struct chunk *a = iv_container_of(_a, struct chunk, an);
		const struct chunk *b = iv_container_of(_b, struct chunk, an);

		return memcmp(a->data, b->data, hash_size);
	}


	int i;
	struct state st;

	for (i = 0; i < 65536; i++)
		INIT_IV_AVL_TREE(&chunks[i], compare_chunks);

	st.chunks = chunks;
	st.hash_size = hash_size;
	st.num_images = num_images;
	st.bitmap_bytes = (num_images + CHAR_BIT - 1) / CHAR_BIT;
	pthread_mutex_init(&st.lock_images, NULL);
	st.an = iv_avl_tree_min(images);
	for (i = 0; i < 65536; i++)
		pthread_mutex_init(&st.lock_chunks[i], NULL);

	run_threads(image_scan_thread, &st, 2 * sysconf(_SC_NPROCESSORS_ONLN));
	printf("\n");

	pthread_mutex_destroy(&st.lock_images);
	for (i = 0; i < 65536; i++)
		pthread_mutex_destroy(&st.lock_chunks[i]);
}
