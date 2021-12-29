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
#include <string.h>
#include <unistd.h>
#include "enumerate_images.h"

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

static int add_image(struct iv_avl_tree *images, struct repo *r,
		     const char *path, int pathlen)
{
	struct image *im;

	im = malloc(sizeof(*im) + pathlen + 1);
	if (im == NULL)
		return -1;

	im->missing_chunks = 0;
	im->r = r;
	memcpy(im->path, path, pathlen);
	im->path[pathlen] = 0;

	iv_avl_tree_insert(images, &im->an);

	return 0;
}

static int scan_image_dir(struct iv_avl_tree *images, struct repo *r,
			  int dirfd, const char *path, int pathlen)
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
				scan_image_dir(images, r, cfd, path2, path2len);
				close(cfd);
			}
		} else if (d_type == DT_REG) {
			add_image(images, r, path2, path2len);
		}

		free(path2);
	}

	closedir(dirp);

	return 0;
}

int enumerate_images(struct iv_avl_tree *images, struct reposet *rs)
{
	struct iv_list_head *lh;
	int i;
	struct iv_avl_node *an;

	INIT_IV_AVL_TREE(images, compare_images);

	iv_list_for_each (lh, &rs->repos) {
		struct repo *r;

		r = iv_container_of(lh, struct repo, list);
		scan_image_dir(images, r, r->imagedir, "", 0);
	}

	i = 0;
	iv_avl_tree_for_each (an, images) {
		struct image *im;

		im = iv_container_of(an, struct image, an);
		im->index = i++;
	}

	return i;
}
