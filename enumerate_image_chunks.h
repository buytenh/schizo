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

#ifndef __ENUMERATE_IMAGE_CHUNKS_H
#define __ENUMERATE_IMAGE_CHUNKS_H

#include <iv_avl.h>
#include "enumerate_images.h"
#include "reposet.h"

struct chunk {
	struct iv_avl_node	an;

	/* hash followed by image bitmap  */
	uint8_t			data[];
};

struct chunk *find_chunk(struct iv_avl_tree *tree,
			 const uint8_t *hash, int hash_size);

void enumerate_image_chunks(struct iv_avl_tree *chunks, int hash_size,
			    int num_images, struct iv_avl_tree *images);


#endif
