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

#ifndef __RW_H
#define __RW_H

#include <errno.h>
#include <unistd.h>

static inline ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t processed;

	processed = 0;
	while (processed < count) {
		ssize_t ret;

		do {
			ret = pread(fd, buf, count - processed, offset);
		} while (ret < 0 && errno == EINTR);

		if (ret <= 0) {
			if (ret < 0)
				perror("pread");
			return processed ? processed : ret;
		}

		buf += ret;
		offset += ret;

		processed += ret;
	}

	return processed;
}

static inline ssize_t xwrite(int fd, const void *buf, size_t count)
{
	ssize_t processed;

	processed = 0;
	while (processed < count) {
		ssize_t ret;

		do {
			ret = write(fd, buf, count - processed);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			perror("write");
			return processed ? processed : ret;
		}

		buf += ret;

		processed += ret;
	}

	return processed;
}

static inline ssize_t
xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t processed;

	processed = 0;
	while (processed < count) {
		ssize_t ret;

		do {
			ret = pwrite(fd, buf, count - processed, offset);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			perror("pwrite");
			return processed ? processed : ret;
		}

		buf += ret;
		offset += ret;

		processed += ret;
	}

	return processed;
}


#endif
