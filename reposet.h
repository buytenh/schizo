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
#include <sys/stat.h>

#define MAX_REPOS		256

struct reposet {
	int			hash_algo;
	int			hash_size;

	int			num_repos;
	struct repo		*repos[MAX_REPOS];

	unsigned int		repo_read;
};

struct repo {
	const char		*path;
	int			repodir;
	int			chunkdir;
	int			corruptdir;
	int			deldir;
	int			imagedir;
	int			tmpdir;
};

struct image_info {
	uint64_t	numchunks;
	uint64_t	size;
	uint32_t	size_firstchunk;
};

void reposet_init(struct reposet *rs);

void reposet_set_hash_algo(struct reposet *rs, int hash_algo);

void reposet_set_hash_size(struct reposet *rs, int hash_size);

int reposet_add_repo(struct reposet *rs, const char *path);

int reposet_open_image(const struct reposet *rs,
		       const char *image, mode_t mode);

int reposet_stat_image(const struct reposet *rs, int fd,
		       struct image_info *info, struct stat *buf);

int reposet_read_chunk(struct reposet *rs, const uint8_t *hash,
		       uint8_t *data, int datalen);

int reposet_undelete_chunk(const struct reposet *rs, const uint8_t *hash);

int reposet_write_image(const struct reposet *rs, const char *image,
			const uint8_t *hashes, uint64_t num_chunks,
			const struct timespec *times);

int reposet_write_chunk(const struct reposet *rs, const uint8_t *hash,
			const uint8_t *data, int datalen,
			const struct timespec *times);


#endif
