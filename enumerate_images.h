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

#ifndef __ENUMERATE_IMAGES_H
#define __ENUMERATE_IMAGES_H

#include <iv_avl.h>
#include <iv_list.h>
#include "reposet.h"

struct image {
	struct iv_avl_node	an;
	int			index;
	struct repo		*r;

	/* for fsck  */
	uint64_t		missing_chunks;

	char			path[];
};

int enumerate_images(struct iv_avl_tree *images, struct reposet *rs);


#endif
