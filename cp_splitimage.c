/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2020, 2022 Lennert Buytenhek
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
#include <stdbool.h>
#include <string.h>
#include "enumerate_chunks.h"
#include "rw.h"
#include "schizo.h"
#include "threads.h"
#include "tty.h"

struct chunk {
	struct iv_avl_node	an;
	uint64_t		index;
};

static uint8_t *hashes;
static uint64_t num;
static uint64_t num_duplicate;
static int section_used[65536];
static struct iv_avl_tree chunks_hash[65536];
static uint64_t num_removed;
static struct iv_avl_tree chunks_write;

struct scan_thread_state {
	uint64_t	num_removed;
};

static int read_hashes(int fd)
{
	int64_t hashes_len;

	hashes_len = lseek(fd, 0, SEEK_END);
	if (hashes_len == (off_t)-1) {
		perror("lseek");
		return 1;
	}

	if (hashes_len > INT_MAX || (hashes_len % hash_size) != 0) {
		fprintf(stderr, "invalid map file length %" PRId64 "\n",
			hashes_len);
		return 1;
	}

	hashes = malloc(hashes_len);
	if (hashes == NULL) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	if (xpread(fd, hashes, hashes_len, 0) != hashes_len)
		return 1;

	num = hashes_len / hash_size;

	return 0;
}

static int compare_chunks_hash(const struct iv_avl_node *_a,
			       const struct iv_avl_node *_b)
{
	const struct chunk *a = iv_container_of(_a, struct chunk, an);
	const struct chunk *b = iv_container_of(_b, struct chunk, an);

	return memcmp(hashes + (a->index * hash_size),
		      hashes + (b->index * hash_size), hash_size);
}

static struct chunk *find_chunk(struct iv_avl_tree *tree, const uint8_t *hash)
{
	struct iv_avl_node *an;

	an = tree->root;
	while (an != NULL) {
		struct chunk *c;
		int ret;

		c = iv_container_of(an, struct chunk, an);

		ret = memcmp(hash, hashes + (c->index * hash_size), hash_size);
		if (ret == 0)
			return c;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static void build_tree_hash(void)
{
	uint64_t i;

	num_duplicate = 0;
	memset(&section_used, 0, sizeof(section_used));
	for (i = 0; i < 65536; i++)
		INIT_IV_AVL_TREE(&chunks_hash[i], compare_chunks_hash);

	for (i = 0; i < num; i++) {
		uint8_t *hash;
		int section;
		struct chunk *c;

		hash = hashes + i * hash_size;
		section = (hash[0] << 8) | hash[1];

		c = find_chunk(&chunks_hash[section], hash);
		if (c == NULL) {
			c = malloc(sizeof(*c));
			if (c == NULL) {
				fprintf(stderr, "out of memory\n");
				exit(EXIT_FAILURE);
			}

			c->index = i;
			iv_avl_tree_insert(&chunks_hash[section], &c->an);
		} else {
			num_duplicate++;
		}
	}
}

static void scan_thread_init(void *_sts)
{
	struct scan_thread_state *sts = _sts;

	sts->num_removed = 0;
}

static void got_section(void *_sts, int section)
{
	section_used[section] = 1;
}

static void got_chunk(void *_sts, int section, const char *dir, int dirfd,
		      const char *name, const uint8_t *hash)
{
	struct scan_thread_state *sts = _sts;
	struct chunk *c;

	c = find_chunk(&chunks_hash[section], hash);
	if (c != NULL) {
		iv_avl_tree_delete(&chunks_hash[section], &c->an);
		free(c);

		sts->num_removed++;
	}
}

static void scan_thread_deinit(void *_sts)
{
	struct scan_thread_state *sts = _sts;

	num_removed += sts->num_removed;
}

static void delete_chunk(struct iv_avl_node *an)
{
	if (an->left != NULL)
		delete_chunk(an->left);
	if (an->right != NULL)
		delete_chunk(an->right);

	free(iv_container_of(an, struct chunk, an));

	num_removed++;
}

static void scan_repos(void)
{
	int i;

	num_removed = 0;
	for (i = 0; i < rs.num_repos; i++) {
		struct repo *r;

		r = rs.repos[i];

		enumerate_chunks(r, hash_size,
				 sizeof(struct scan_thread_state),
				 128, scan_thread_init, got_section,
				 got_chunk, scan_thread_deinit);
	}

	for (i = 0; i < 65536; i++) {
		if (!section_used[i] && chunks_hash[i].root != NULL) {
			delete_chunk(chunks_hash[i].root);
			chunks_hash[i].root = NULL;
		}
	}
}

static int compare_chunks_index(const struct iv_avl_node *_a,
				const struct iv_avl_node *_b)
{
	const struct chunk *a = iv_container_of(_a, struct chunk, an);
	const struct chunk *b = iv_container_of(_b, struct chunk, an);

	if (a->index < b->index)
		return -1;
	if (a->index > b->index)
		return 1;

	return 0;
}

static void insert_tree_write(struct iv_avl_node *an)
{
	if (an->left != NULL)
		insert_tree_write(an->left);
	if (an->right != NULL)
		insert_tree_write(an->right);

	iv_avl_tree_insert(&chunks_write, an);
}

static void build_tree_write(bool by_hash)
{
	int i;

	if (by_hash)
		INIT_IV_AVL_TREE(&chunks_write, compare_chunks_hash);
	else
		INIT_IV_AVL_TREE(&chunks_write, compare_chunks_index);

	for (i = 0; i < 65536; i++) {
		if (chunks_hash[i].root != NULL)
			insert_tree_write(chunks_hash[i].root);
	}
}

static int fd_imgfile;
static uint32_t last_block_size;
static struct timespec times[2];
static pthread_mutex_t lock;
static uint64_t i;
static struct iv_avl_node *an;
static int errors_seen;

static int write_chunk(uint64_t index, int datalen)
{
	const uint8_t *hash;
	uint8_t data[block_size];

	hash = hashes + index * hash_size;

	if (fd_imgfile == -1) {
		if (reposet_read_chunk(&rs_src, hash, data, datalen) < 0)
			return 1;
	} else {
		ssize_t ret;
		uint8_t computed_hash[hash_size];

		ret = xpread(fd_imgfile, data, datalen, index * block_size);
		if (ret != datalen)
			return 1;

		gcry_md_hash_buffer(hash_algo, computed_hash, data, datalen);

		if (memcmp(hash, computed_hash, hash_size)) {
			fprintf(stderr, "write_chunk: hash mismatch "
					"for chunk %jd\n", (intmax_t)index);
			return 1;
		}
	}

	if (reposet_write_chunk(&rs, hash, data, datalen, times) == 0)
		return 1;

	return 0;
}

static void *write_thread(void *_dummy)
{
	int err;

	pthread_mutex_lock(&lock);

	err = 0;
	while (an != NULL) {
		struct chunk *c;
		uint32_t this_block_size;

		c = iv_container_of(an, struct chunk, an);
		an = iv_avl_tree_next(an);

		pthread_mutex_unlock(&lock);

		if (c->index == num - 1)
			this_block_size = last_block_size;
		else
			this_block_size = block_size;

		err |= write_chunk(c->index, this_block_size);

		pthread_mutex_lock(&lock);

		if (stderr_is_tty()) {
			fprintf(stderr,
                                "\r%" PRId64 "/%" PRId64 " (block %" PRId64 ")",
			        ++i, num - num_duplicate - num_removed,
			        c->index);
		}
	}

	errors_seen |= err;

	pthread_mutex_unlock(&lock);

	return NULL;
}

static int cp_splitimage(const char *image, const struct timespec *mtime)
{
	build_tree_hash();

	scan_repos();

	build_tree_write(!!(fd_imgfile == -1));

	times[0].tv_sec = 0;
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = mtime->tv_sec;
	times[1].tv_nsec = mtime->tv_nsec;

	pthread_mutex_init(&lock, NULL);
	i = 0;
	an = iv_avl_tree_min(&chunks_write);
	errors_seen = 0;

	run_threads(write_thread, NULL, 128);
	if (stderr_is_tty()) {
		fprintf(stderr, "\n");
	}

	if (!errors_seen)
		reposet_write_image(&rs, image, hashes, num, times);

	free(hashes);

	if (fd_imgfile != -1)
		close(fd_imgfile);

	return errors_seen;
}

int cp(int argc, char *argv[])
{
	int fd_mapfile;
	struct image_info info;
	struct stat buf;

	if (argc != 1)
		return -1;

	fd_mapfile = reposet_open_image(&rs_src, argv[0], O_RDONLY);
	if (fd_mapfile < 0) {
		perror("open");
		return 1;
	}

	if (reposet_stat_image(&rs_src, fd_mapfile, &info, &buf) < 0) {
		perror("fstat");
		close(fd_mapfile);
		return 1;
	}

	if (info.size_firstchunk != block_size) {
		fprintf(stderr, "image has block size %jd while "
				"configured block size is %jd\n",
			(intmax_t)info.size_firstchunk, (intmax_t)block_size);
		close(fd_mapfile);
		return 1;
	}

	if (read_hashes(fd_mapfile)) {
		close(fd_mapfile);
		return 1;
	}

	close(fd_mapfile);

	fd_imgfile = -1;

	last_block_size = info.size -
				(info.numchunks - 1) * info.size_firstchunk;

	return cp_splitimage(argv[0], &buf.st_mtim);
}

int splitimage(int argc, char *argv[])
{
	int fd_mapfile;
	struct stat buf;
	uint64_t num_blocks;

	if (argc != 3)
		return -1;

	fd_mapfile = open(argv[2], O_RDONLY);
	if (fd_mapfile < 0) {
		perror("open");
		return 1;
	}

	if (read_hashes(fd_mapfile)) {
		close(fd_mapfile);
		return 1;
	}

	close(fd_mapfile);

	fd_imgfile = open(argv[1], O_RDONLY);
	if (fd_imgfile < 0) {
		perror("open");
		free(hashes);
		return 1;
	}

	if (fstat(fd_imgfile, &buf) < 0) {
		perror("fstat");
		free(hashes);
		close(fd_imgfile);
		return 1;
	}

	num_blocks = (buf.st_size + block_size - 1) / block_size;
	if (num_blocks != num) {
		fprintf(stderr, "image file has %" PRId64 " blocks "
				"while map file has %" PRId64 "\n",
			num_blocks, num);
		free(hashes);
		close(fd_imgfile);
		return 1;
	}

	last_block_size = buf.st_size - (num - 1) * block_size;

	return cp_splitimage(argv[0], &buf.st_mtim);
}
