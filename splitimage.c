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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include "rw.h"
#include "schizo.h"

int splitimage(int argc, char *argv[])
{
	int fd;
	int64_t hashes_len;
	uint8_t *hashes;
	struct stat buf;
	uint64_t size;
	uint64_t num_blocks;
	uint32_t last_block_size;
	struct timespec times[2];
	uint64_t i;

	if (argc != 3)
		return -1;

	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	hashes_len = lseek(fd, 0, SEEK_END);
	if (hashes_len == (off_t)-1) {
		perror("lseek");
		return 1;
	}

	if (hashes_len < 0 || hashes_len > INT_MAX) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	hashes = malloc(hashes_len);
	if (hashes == NULL) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	if (xpread(fd, hashes, hashes_len, 0) != hashes_len)
		return 1;

	close(fd);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (fstat(fd, &buf) < 0) {
		perror("fstat");
		return 1;
	}

	size = buf.st_size;
	num_blocks = (size + block_size - 1) / block_size;
	last_block_size = size - (num_blocks - 1) * block_size;

	times[0].tv_sec = 0;
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = buf.st_mtim.tv_sec;
	times[1].tv_nsec = buf.st_mtim.tv_nsec;

	for (i = 0; i < num_blocks; i++) {
		uint32_t this_block_size;

		if ((i % 1000) == 0) {
			printf("\r%jd/%jd", (intmax_t)i, (intmax_t)num_blocks);
			fflush(stdout);
		}

		if (i == num_blocks - 1)
			this_block_size = last_block_size;
		else
			this_block_size = block_size;

		reposet_write_chunk_fromfd(&rs, hashes + i * hash_size,
					   fd, i * block_size,
					   this_block_size, times);
	}

	printf("\n");

	close(fd);

	reposet_write_image(&rs, argv[0], hashes, num_blocks, times);

	return 0;
}
