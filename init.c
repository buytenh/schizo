/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2020 Lennert Buytenhek
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
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "schizo.h"
#include "threads.h"

static int pattern_length;
static uint8_t *pattern;
static int chunkdir;

static pthread_mutex_t lock;
static int dir_index;
static int err;

static void *mkdir_thread(void *_dummy)
{
	pthread_mutex_lock(&lock);

	while (1) {
		int i;
		char name[16];
		int dirfd;
		int j;

		i = dir_index;
		if (i == 256)
			break;

		dir_index++;

		snprintf(name, sizeof(name), "%.2x", i);

		if (mkdirat(chunkdir, name, 0777) < 0 && errno != EEXIST) {
			perror("mkdir");
			err = 1;
			break;
		}

		pthread_mutex_unlock(&lock);

		dirfd = openat(chunkdir, name, O_DIRECTORY | O_PATH);
		if (dirfd < 0) {
			perror("open");
			err = 1;
			return NULL;
		}

		for (j = 0; j < 256; j++) {
			int section;

			section = (i << 8) | j;
			if (pattern[section % pattern_length]) {
				snprintf(name, sizeof(name), "%.2x", j);

				if (mkdirat(dirfd, name, 0777) < 0 &&
				    errno != EEXIST) {
					perror("mkdir");
					err = 1;
					return NULL;
				}
			}
		}

		close(dirfd);

		pthread_mutex_lock(&lock);
	}

	pthread_mutex_unlock(&lock);

	return NULL;
}

int init(int argc, char *argv[])
{
	int i;

	if (argc == 0) {
		pattern_length = 1;
		pattern = alloca(pattern_length);

		pattern[0] = 1;
	} else if (argc == 1) {
		pattern_length = strlen(argv[0]);
		pattern = alloca(pattern_length);

		for (i = 0; i < pattern_length; i++) {
			char c;

			c = argv[0][i];
			if (c == 'X' || c == 'x')
				pattern[i] = 1;
			else
				pattern[i] = 0;
		}
	} else {
		return 1;
	}

	if (mkdir("chunks", 0777) < 0 && errno != EEXIST) {
		perror("mkdir");
		return 1;
	}

	chunkdir = openat(AT_FDCWD, "chunks", O_DIRECTORY | O_PATH);
	if (chunkdir < 0) {
		perror("open");
		return 1;
	}

	pthread_mutex_init(&lock, NULL);
	dir_index = 0;
	err = 0;

	run_threads(mkdir_thread, NULL, 128);

	pthread_mutex_destroy(&lock);

	if (err)
		return 1;

	close(chunkdir);

	if (mkdir("images", 0777) < 0 && errno != EEXIST) {
		perror("mkdir");
		return 1;
	}

	return 0;
}
