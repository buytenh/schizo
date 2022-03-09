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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "base64dec.h"
#include "enumerate_chunks.h"
#include "threads.h"

struct repo_scan_state {
	struct repo		*r;
	int			hash_size;
	int			tls_size;
	void			(*thread_init)(void *st);
	void			(*got_section)(void *st, int section);
	void			(*got_chunk)(void *st, int section,
					     const char *dir, int dirfd,
					     const char *name,
					     const uint8_t *hash);
	void			(*thread_deinit)(void *st);

	pthread_mutex_t		lock;
	int			section;
};

static void scan_section(struct repo_scan_state *rss, void *st, int section)
{
	char dir[16];
	int dirfd;
	DIR *dirp;

	snprintf(dir, sizeof(dir), "%.2x/%.2x",
		 (section >> 8) & 0xff, section & 0xff);

	dirfd = openat(rss->r->chunkdir, dir, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0) {
		if (errno != ENOENT)
			perror("openat");
		return;
	}

	dirp = fdopendir(dirfd);
	if (dirp == NULL) {
		perror("fdopendir");
		close(dirfd);
		return;
	}

	if (rss->got_section != NULL)
		rss->got_section(st, section);

	while (1) {
		struct dirent *dent;
		unsigned char d_type;
		uint8_t hash[rss->hash_size];
		int ret;

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
			if (ret == 0 && (sbuf.st_mode & S_IFMT) == S_IFREG)
				d_type = DT_REG;
		}

		if (d_type != DT_REG) {
			fprintf(stderr, "found strange entry: %s/%s\n",
				dir, dent->d_name);
			continue;
		}

		if (strlen(dent->d_name) != B64SIZE(rss->hash_size)) {
			fprintf(stderr, "found odd-length file name: %s/%s\n",
				dir, dent->d_name);
			continue;
		}

		ret = base64dec(hash, dent->d_name, B64SIZE(rss->hash_size));
		if (ret < 0) {
			fprintf(stderr, "found undecodable file name: %s/%s\n",
				dir, dent->d_name);
			continue;
		}

		if (hash[0] != ((section >> 8) & 0xff) ||
		    hash[1] != (section & 0xff)) {
			fprintf(stderr, "found chunk in the wrong dir: %s/%s\n",
				dir, dent->d_name);
		}

		rss->got_chunk(st, section, dir, dirfd, dent->d_name, hash);
	}

	closedir(dirp);
}

static void *repo_scan_thread(void *_rss)
{
	struct repo_scan_state *rss = _rss;
	void *st;

	st = alloca(rss->tls_size);
	rss->thread_init(st);

	pthread_mutex_lock(&rss->lock);

	while (rss->section < 0x10000) {
		int section;

		section = rss->section++;

		printf("scanning %.4x\b\b\b\b\b\b\b\b\b\b\b\b\b", section);
		fflush(stdout);

		pthread_mutex_unlock(&rss->lock);
		scan_section(rss, st, section);
		pthread_mutex_lock(&rss->lock);
	}

	rss->thread_deinit(st);

	pthread_mutex_unlock(&rss->lock);

	return NULL;
}

void enumerate_chunks(struct repo *r, int hash_size, int tls_size,
		      int nthreads,
		      void (*thread_init)(void *st),
		      void (*got_section)(void *st, int section),
		      void (*got_chunk)(void *st, int section,
					const char *dir, int dirfd,
					const char *name, const uint8_t *hash),
		      void (*thread_deinit)(void *st))
{
	struct repo_scan_state rss;

	rss.r = r;
	rss.hash_size = hash_size;
	rss.tls_size = tls_size;
	rss.thread_init = thread_init;
	rss.got_section = got_section;
	rss.got_chunk = got_chunk;
	rss.thread_deinit = thread_deinit;
	pthread_mutex_init(&rss.lock, NULL);
	rss.section = 0;

	run_threads(repo_scan_thread, &rss, nthreads);

	pthread_mutex_destroy(&rss.lock);
}
