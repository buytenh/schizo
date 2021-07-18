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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <iv_avl.h>
#include <iv_list.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "base64enc.h"
#include "reposet.h"
#include "threads.h"

struct image {
	struct iv_avl_node	an;
	int			index;
	uint64_t		missing_chunks;
	struct repo		*r;
	char			path[];
};

struct chunk {
	struct iv_avl_node	an;
	uint8_t			hash_bitmap[];
};

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static struct reposet rs;

static int num_images;
static struct iv_avl_tree images;
static int bitmap_bytes;
static struct iv_avl_tree chunks[65536];

static int
compare_images(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
	const struct image *a = iv_container_of(_a, struct image, an);
	const struct image *b = iv_container_of(_b, struct image, an);
	int ret;

	ret = strcmp(a->r->path, b->r->path);
	if (ret)
		return ret;

	return strcmp(a->path, b->path);
}

static int add_image(struct repo *r, const char *path, int pathlen)
{
	struct image *im;

	im = malloc(sizeof(*im) + pathlen + 1);
	if (im == NULL)
		return -1;

	im->missing_chunks = 0;
	im->r = r;
	memcpy(im->path, path, pathlen);
	im->path[pathlen] = 0;

	iv_avl_tree_insert(&images, &im->an);

	return 0;
}

static int
scan_image_dir(struct repo *r, int dirfd, const char *path, int pathlen)
{
	int fd;
	DIR *dirp;

	fd = openat(dirfd, ".", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		perror("openat");
		return -1;
	}

	dirp = fdopendir(fd);
	if (dirp == NULL) {
		perror("fdopendir");
		close(fd);
		return -1;
	}

	while (1) {
		struct dirent *dent;
		unsigned char d_type;
		int len;
		char *path2;
		int path2len;

		errno = 0;

		dent = readdir(dirp);
		if (dent == NULL) {
			if (errno)
				perror("readdir");
			break;
		}

		if (strcmp(dent->d_name, ".") == 0)
			continue;
		if (strcmp(dent->d_name, "..") == 0)
			continue;

		d_type = dent->d_type;
		if (d_type == DT_UNKNOWN) {
			struct stat sbuf;
			int ret;

			ret = fstatat(dirfd, dent->d_name, &sbuf, 0);
			if (ret == 0) {
				if ((sbuf.st_mode & S_IFMT) == S_IFDIR)
					d_type = DT_DIR;
				else if ((sbuf.st_mode & S_IFMT) == S_IFREG)
					d_type = DT_REG;
			}
		}

		if (d_type != DT_DIR && d_type != DT_REG)
			continue;

		len = strlen(dent->d_name);

		path2len = pathlen + 1 + len;

		path2 = malloc(path2len + 1);
		if (path2 == NULL)
			continue;

		memcpy(path2, path, pathlen);
		path2[pathlen] = '/';
		memcpy(path2 + pathlen + 1, dent->d_name, len);
		path2[path2len] = 0;

		if (d_type == DT_DIR) {
			int cfd;

			cfd = openat(dirfd, dent->d_name, O_DIRECTORY | O_PATH);
			if (cfd >= 0) {
				scan_image_dir(r, cfd, path2, path2len);
				close(cfd);
			}
		} else if (d_type == DT_REG) {
			add_image(r, path2, path2len);
		}

		free(path2);
	}

	closedir(dirp);

	return 0;
}

static void enumerate_images(void)
{
	struct iv_list_head *lh;
	int i;
	struct iv_avl_node *an;

	num_images = 0;
	INIT_IV_AVL_TREE(&images, compare_images);

	iv_list_for_each (lh, &rs.repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);
		scan_image_dir(r, r->imagedir, "", 0);
	}

	i = 0;
	iv_avl_tree_for_each (an, &images) {
		struct image *im;

		im = iv_container_of(an, struct image, an);
		im->index = i++;
	}

	num_images = i;
}

static int
compare_chunks(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
	const struct chunk *a = iv_container_of(_a, struct chunk, an);
	const struct chunk *b = iv_container_of(_b, struct chunk, an);

	return memcmp(a->hash_bitmap, b->hash_bitmap, hash_size);
}

static struct chunk *find_chunk(struct iv_avl_tree *tree, const uint8_t *hash)
{
	struct iv_avl_node *an;

	an = tree->root;
	while (an != NULL) {
		struct chunk *c;
		int ret;

		c = iv_container_of(an, struct chunk, an);

		ret = memcmp(hash, c->hash_bitmap, hash_size);
		if (ret == 0)
			return c;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static struct chunk *get_chunk(struct iv_avl_tree *tree, const uint8_t *hash)
{
	struct chunk *c;

	c = find_chunk(tree, hash);
	if (c != NULL)
		return c;

	c = malloc(sizeof(*c) + hash_size + bitmap_bytes);
	if (c == NULL)
		return NULL;

	memcpy(c->hash_bitmap, hash, hash_size);
	memset(c->hash_bitmap + hash_size, 0, bitmap_bytes);
	iv_avl_tree_insert(tree, &c->an);

	return c;
}

static void scan_images(void)
{
	struct iv_avl_node *an;
	int i;

	bitmap_bytes = (num_images + CHAR_BIT - 1) / CHAR_BIT;
	for (i = 0; i < 65536; i++)
		INIT_IV_AVL_TREE(&chunks[i], compare_chunks);

	iv_avl_tree_for_each (an, &images) {
		struct image *im;
		int fd;
		FILE *fp;

		im = iv_container_of(an, struct image, an);

		printf("scanning %d/%d %s\r", im->index + 1, num_images,
		       im->path + 1);
		fflush(stdout);

		fd = openat(im->r->imagedir, im->path + 1, O_RDONLY);
		if (fd < 0) {
			perror("openat");
			continue;
		}

		fp = fdopen(fd, "r");
		if (fp == NULL) {
			perror("fdopen");
			close(fd);
			continue;
		}

		while (1) {
			uint8_t hash[hash_size];
			size_t ret;
			int section;
			struct chunk *c;

			ret = fread(hash, 1, hash_size, fp);
			if (ret != hash_size) {
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

			c = get_chunk(&chunks[section], hash);
			if (c == NULL) {
				fprintf(stderr, "out of memory\n");
				break;
			}

			c->hash_bitmap[hash_size + (im->index / CHAR_BIT)] |=
				1 << (im->index % CHAR_BIT);
		}

		fclose(fp);
	}

	printf("\n");
}

static struct iv_avl_node *__first_chunk(int start_section)
{
	int i;

	for (i = start_section; i < 65536; i++) {
		struct iv_avl_node *an;

		an = iv_avl_tree_min(&chunks[i]);
		if (an != NULL)
			return an;
	}

	return NULL;
}

static struct iv_avl_node *first_chunk(void)
{
	return __first_chunk(0);
}

static struct iv_avl_node *next_chunk(struct iv_avl_node *an)
{
	struct iv_avl_node *next;
	struct chunk *c;
	int section;

	next = iv_avl_tree_next(an);
	if (next != NULL)
		return next;

	c = iv_container_of(an, struct chunk, an);
	section = (c->hash_bitmap[0] << 8) | c->hash_bitmap[1];

	return __first_chunk(section + 1);
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

struct chunk_scan_state {
	pthread_mutex_t		lock;
	struct iv_avl_node	*an;
	int			last;
	uint64_t		num;
	uint64_t		missing;
};

static void *chunk_scan_thread(void *_css)
{
	struct chunk_scan_state *css = _css;

	pthread_mutex_lock(&css->lock);

	while (css->an != NULL) {
		struct chunk *c;
		int section;
		int fd;

		c = iv_container_of(css->an, struct chunk, an);
		css->an = next_chunk(css->an);

		section = (c->hash_bitmap[0] << 8) | c->hash_bitmap[1];
		if (css->last != section) {
			css->last = section;
			printf("scanning %.4x\b\b\b\b\b\b\b"
			       "\b\b\b\b\b\b", section);
			fflush(stdout);
		}

		pthread_mutex_unlock(&css->lock);

		fd = reposet_open_chunk(&rs, c->hash_bitmap);
		if (fd >= 0)
			close(fd);

		pthread_mutex_lock(&css->lock);

		if (fd < 0) {
			char name[B64SIZE(hash_size) + 1];
			uint8_t *bm;
			int i;

			css->missing++;

			base64enc(name, c->hash_bitmap, hash_size);
			fprintf(stderr, "can't find chunk %s\n", name);

			bm = c->hash_bitmap + hash_size;

			for (i = 0; i < num_images; i++) {
				if (bm[i / CHAR_BIT] & 1 << (i % CHAR_BIT))
					find_image(i)->missing_chunks++;
			}
		} else {
			css->num++;
		}
	}

	pthread_mutex_unlock(&css->lock);

	return NULL;
}

static void scan_chunks(void)
{
	struct chunk_scan_state css;

	pthread_mutex_init(&css.lock, NULL);
	css.an = first_chunk();
	css.last = -1;
	css.num = 0;
	css.missing = 0;

	run_threads(chunk_scan_thread, &css, 128);

	pthread_mutex_destroy(&css.lock);

	printf("scanned %" PRId64 " chunks", css.num);
	if (css.missing)
		printf(", %" PRId64 " missing", css.missing);
	printf("\n");
}

static void report_missing_chunks(void)
{
	struct iv_avl_node *an;

	iv_avl_tree_for_each (an, &images) {
		struct image *im;

		im = iv_container_of(an, struct image, an);
		if (im->missing_chunks) {
			printf("%s %s: %" PRId64 " missing chunk(s)\n",
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

	enumerate_images();

	scan_images();

	scan_chunks();

	report_missing_chunks();

	return 0;
}
