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
#include "base64dec.h"

static int base64url_index(char c)
{
	if (c >= 'A' && c <= 'Z')
		return  0 + (c - 'A');
	if (c >= 'a' && c <= 'z')
		return 26 + (c - 'a');
	if (c >= '0' && c <= '9')
		return 52 + (c - '0');
	if (c == '-')
		return 62;
	if (c == '_')
		return 63;

	return -1;
}

int base64dec(uint8_t *data, const char *b64, int len)
{
	int i;
	int j;

	i = 0;
	j = 0;
	while (i < len) {
		int toread;
		int val;
		int k;

		toread = len - i;
		if (toread == 1)
			return -1;

		if (toread > 4)
			toread = 4;

		val = 0;
		for (k = 0; k < toread; k++) {
			int val2;

			val2 = base64url_index(b64[i++]);
			if (val2 < 0)
				return -1;

			val |= val2 << (18 - (6 * k));
		}

		for (k = 1; k < toread; k++) {
			data[j++] = (val >> 16) & 0xff;
			val <<= 8;
		}
	}

	return 0;
}
