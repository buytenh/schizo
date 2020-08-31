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
#include "base64enc.h"

static const char *base64url =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void base64enc(char *b64, const uint8_t *data, int len)
{
	int outlen;
	int i;
	int j;

	outlen = B64SIZE(len);

	i = 0;
	j = 0;
	while (i < len) {
		int val;

		val = data[i++] << 16;
		if (i < len)
			val |= data[i++] << 8;
		if (i < len)
			val |= data[i++];

		b64[j++] = base64url[(val >> 18) & 0x3f];
		if (j < outlen)
			b64[j++] = base64url[(val >> 12) & 0x3f];
		if (j < outlen)
			b64[j++] = base64url[(val >> 6) & 0x3f];
		if (j < outlen)
			b64[j++] = base64url[val & 0x3f];
	}

	b64[j++] = 0;
}
