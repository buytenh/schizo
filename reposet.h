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

#ifndef __REPOSET_H
#define __REPOSET_H

#include <inttypes.h>
#include <iv_list.h>
#include <sys/stat.h>

struct reposet {
	struct iv_list_head	repos;
	int			hash_size;
};

struct repo {
	struct iv_list_head	list;
	const char		*path;
	int			chunkdir;
	int			imagedir;
};

struct image_info {
	uint64_t	numchunks;
	uint64_t	size;
	uint32_t	size_firstchunk;
};

void reposet_init(struct reposet *rs);

void reposet_set_hash_size(struct reposet *rs, int hash_size);

int reposet_add_repo(struct reposet *rs, const char *path);

int reposet_open_image(const struct reposet *rs,
		       const char *image, mode_t mode);

int reposet_stat_image(const struct reposet *rs, int fd,
		       struct image_info *info, struct stat *buf);

int reposet_open_chunk(const struct reposet *rs, const uint8_t *hash);

int reposet_write_image(const struct reposet *rs, const char *image,
			const uint8_t *hashes, uint64_t num_chunks,
			const struct timespec *times);

int reposet_write_chunk_frombuf(const struct reposet *rs, const uint8_t *hash,
				const uint8_t *data, int datalen,
				const struct timespec *times);

int reposet_write_chunk_fromfd(const struct reposet *rs, const uint8_t *hash,
			       int srcfd, uint64_t off, int datalen,
			       const struct timespec *times);


#endif
