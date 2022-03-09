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

#ifndef __ENUMERATE_CHUNKS_H
#define __ENUMERATE_CHUNKS_H

#include "reposet.h"

void enumerate_chunks(struct repo *r, int hash_size, int tls_size,
		      int nthreads,
		      void (*thread_init)(void *st),
		      void (*got_section)(void *st, int section),
		      void (*got_chunk)(void *st, int section,
					const char *dir, int dirfd,
					const char *name, const uint8_t *hash),
		      void (*thread_deinit)(void *st));


#endif
