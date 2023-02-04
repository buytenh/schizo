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
#include <gcrypt.h>
#include <getopt.h>
#include "reposet.h"
#include "schizo.h"

int cp(int argc, char *argv[]);
int fsck(int argc, char *argv[]);
int gc(int argc, char *argv[]);
int init(int argc, char *argv[]);
int scrub(int argc, char *argv[]);
int splitimage(int argc, char *argv[]);

int block_size = 1048576;
int hash_algo = GCRY_MD_SHA512;
int hash_size;
int thread_limit;

struct reposet rs;
struct reposet rs_src;

enum {
	TOOL_UNKNOWN = 0,
	TOOL_CP,
	TOOL_FSCK,
	TOOL_GC,
	TOOL_INIT,
	TOOL_SCRUB,
	TOOL_SPLITIMAGE,
};

static int tool;

static void set_tool(int newtool)
{
	if (tool != TOOL_UNKNOWN) {
		fprintf(stderr, "error: can only select one tool to run\n");
		exit(EXIT_FAILURE);
	}

	tool = newtool;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [opts]\n", argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, " available tools:\n");
	fprintf(stderr, "     --cp                   run cp\n");
	fprintf(stderr, "     --fsck                 run fsck\n");
	fprintf(stderr, "     --gc                   run gc\n");
	fprintf(stderr, "     --init                 run init\n");
	fprintf(stderr, "     --scrub                run scrub\n");
	fprintf(stderr, "     --splitimage           run splitimage\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " global options:\n");
	fprintf(stderr, "  -b, --block-size=SIZE     hash block size\n");
	fprintf(stderr, "  -h, --hash-algo=ALGO      hash algorithm\n");
	fprintf(stderr, "  -r, --repository=DIR      repository\n");
	fprintf(stderr, "  -s, --src-repository=DIR  source repository (cp)\n");
	fprintf(stderr, "  -t, --thread-limit=LIM    worker thread limit\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "cp", no_argument, 0, 'c' },
		{ "fsck", no_argument, 0, 'f' },
		{ "gc", no_argument, 0, 'g' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ "init", no_argument, 0, 'i' },
		{ "repository", required_argument, 0, 'r' },
		{ "scrub", no_argument, 0, 'k' },
		{ "splitimage", no_argument, 0, 'S' },
		{ "src-repository", required_argument, 0, 's' },
		{ "thread-limit", required_argument, 0, 't' },
		{ 0, 0, 0, 0 },
	};
	int ret;

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	reposet_init(&rs);
	reposet_init(&rs_src);

	while (1) {
		int c;

		c = getopt_long(argc, argv, "b:h:r:s:t:", long_options, NULL);
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

		case 'c':
			set_tool(TOOL_CP);
			break;

		case 'f':
			set_tool(TOOL_FSCK);
			break;

		case 'g':
			set_tool(TOOL_GC);
			break;

		case 'h':
			hash_algo = gcry_md_map_name(optarg);
			if (hash_algo == 0) {
				fprintf(stderr, "unknown hash algorithm "
						"name: %s\n", optarg);
				return 1;
			}
			break;

		case 'i':
			set_tool(TOOL_INIT);
			break;

		case 'k':
			set_tool(TOOL_SCRUB);
			break;

		case 'r':
			if (reposet_add_repo(&rs, optarg) < 0) {
				fprintf(stderr, "can't add repo %s\n", optarg);
				return 1;
			}
			break;

		case 'S':
			set_tool(TOOL_SPLITIMAGE);
			break;

		case 's':
			if (reposet_add_repo(&rs_src, optarg) < 0) {
				fprintf(stderr, "can't add src repo %s\n",
					optarg);
				return 1;
			}
			break;

		case 't':
			if (sscanf(optarg, "%i", &thread_limit) != 1) {
				fprintf(stderr, "cannot parse thread limit: "
						"%s\n", optarg);
				return 1;
			}
			if (thread_limit < 1) {
				fprintf(stderr, "thread limit must be a "
						"positive integer\n");
				return 1;
			}
			break;

		case '?':
			return 1;

		default:
			abort();
		}
	}

	if (block_size <= 0 || block_size % 4096) {
		fprintf(stderr, "block size must be a multiple of 4096\n");
		return 1;
	}

	reposet_set_hash_algo(&rs, hash_algo);
	reposet_set_hash_algo(&rs_src, hash_algo);

	hash_size = gcry_md_get_algo_dlen(hash_algo);
	reposet_set_hash_size(&rs, hash_size);
	reposet_set_hash_size(&rs_src, hash_size);

	ret = -1;

	if (tool == TOOL_CP || tool == TOOL_FSCK || tool == TOOL_GC ||
	    tool == TOOL_SCRUB || tool == TOOL_SPLITIMAGE) {
		if (iv_list_empty(&rs.repos)) {
			fprintf(stderr, "missing repositories\n");
			return 1;
		}
	}

	if (tool == TOOL_CP && iv_list_empty(&rs_src.repos)) {
		fprintf(stderr, "missing src repositories\n");
		return 1;
	}

	switch (tool) {
	case TOOL_CP:
		ret = cp(argc - optind, argv + optind);
		break;
	case TOOL_FSCK:
		ret = fsck(argc - optind, argv + optind);
		break;
	case TOOL_GC:
		ret = gc(argc - optind, argv + optind);
		break;
	case TOOL_INIT:
		ret = init(argc - optind, argv + optind);
		break;
	case TOOL_SCRUB:
		ret = scrub(argc - optind, argv + optind);
		break;
	case TOOL_SPLITIMAGE:
		ret = splitimage(argc - optind, argv + optind);
		break;
	}

	if (ret < 0) {
		usage(argv[0]);
		return 1;
	}

	return ret;
}
