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
#include <gcrypt.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "reposet.h"
#include "rw.h"

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static struct reposet rs;

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ "repository", required_argument, 0, 'r' },
		{ 0, 0, 0, 0 },
	};
	int fd;
	int64_t hashes_len;
	uint8_t *hashes;
	struct stat buf;
	uint64_t size;
	uint64_t num_blocks;
	uint32_t last_block_size;
	struct timespec times[2];
	uint64_t i;

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

	if (argc - optind != 3) {
		fprintf(stderr, "syntax: %s [opts] <img> "
				"<img.img> <img.map>\n", argv[0]);
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

	fd = open(argv[optind + 2], O_RDONLY);
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

	fd = open(argv[optind + 1], O_RDONLY);
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

	reposet_write_image(&rs, argv[optind], hashes, num_blocks, times);

	return 0;
}
