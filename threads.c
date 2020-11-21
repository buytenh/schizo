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
#include <pthread.h>
#include <string.h>
#include "threads.h"

void run_threads(void *(*handler)(void *), void *cookie, int nthreads)
{
	pthread_t tid[nthreads];
	int ret;
	int i;

	for (i = 0; i < nthreads; i++) {
		ret = pthread_create(&tid[i], NULL, handler, cookie);
		if (ret) {
			fprintf(stderr, "pthread_create: %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < nthreads; i++) {
		ret = pthread_join(tid[i], NULL);
		if (ret) {
			fprintf(stderr, "pthread_join: %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}
	}
}
