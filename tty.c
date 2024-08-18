/*
 * schizo, a set of tools for managing split disk images
 * Copyright (C) 2024 Lennert Buytenhek
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
#include <errno.h>
#include <unistd.h>
#include "tty.h"

int stderr_is_tty(void)
{
	static int flag = -1;

	if (flag == -1) {
		if (isatty(2)) {
			flag = 1;
		} else if (errno == EINVAL || errno == ENOTTY) {
			flag = 0;
		} else {
			perror("isatty");
			exit(1);
		}
	}

	return flag;
}
