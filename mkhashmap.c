/*
 * replika, a set of tools for dealing with hashmapped disk images
 * Copyright (C) 2015 Lennert Buytenhek
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

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <unistd.h>
#include "common.h"

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;
static int fd_src;
static off_t sizeblocks;
static int fd_hashmap;
static uint8_t *hashmap;
static off_t fd_off;

static void *hash_thread(void *_me)
{
	struct worker_thread *me = _me;

	xsem_wait(&me->sem0);

	while (fd_off < sizeblocks) {
		uint8_t buf[block_size];
		uint8_t hash[hash_size];
		off_t off;
		int ret;

		off = fd_off++;

		posix_fadvise(fd_src, off * block_size, 4 * block_size,
				POSIX_FADV_WILLNEED);

		ret = xpread(fd_src, buf, block_size, off * block_size);

		xsem_post(&me->next->sem0);

		if (ret < block_size && off != sizeblocks - 1) {
			fprintf(stderr, "short read\n");
			return NULL;
		}

		gcry_md_hash_buffer(hash_algo, hash, buf, ret);

		xsem_wait(&me->sem0);

		if (hashmap != NULL && memcmp(hashmap + off * hash_size,
					      hash, hash_size)) {
			xpwrite(fd_hashmap, hash, hash_size, off * hash_size);
			memcpy(hashmap + off * hash_size, hash, hash_size);

			fprintf(stderr, "%Ld ", (long long)off);
			progress_reported();
		} else {
			if (hashmap == NULL) {
				xpwrite(fd_hashmap, hash, hash_size,
					off * hash_size);
			}

			if (should_report_progress()) {
				char str[256];

				ret = sprintf(str, "%Ld/%Ld", (long long)off,
					      (long long)sizeblocks);
				memset(str + ret, '\b', ret);
				str[2 * ret] = 0;

				fputs(str, stderr);
			}
		}
	}

	xsem_post(&me->next->sem0);

	return NULL;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	while (1) {
		int c;

		c = getopt_long(argc, argv, "b:h:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'b':
			if (sscanf(optarg, "%i", &block_size) != 1) {
				fprintf(stderr, "cannot parse block size: "
						"%s\n", optarg);
				return 1;
			}

			if ((block_size & 7) != 0) {
				fprintf(stderr, "error: block size must be "
						"a multiple of 8\n");
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

		case '?':
			return 1;

		default:
			abort();
		}
	}

	if (optind + 2 != argc) {
		fprintf(stderr, "%s: [opts] <image> <hashmap>\n", argv[0]);
		fprintf(stderr, " -b, --block-size=SIZE    hash block size\n");
		fprintf(stderr, " -h, --hash-algo=ALGO     hash algorithm\n");
		return 1;
	}

	hash_size = gcry_md_get_algo_dlen(hash_algo);

	fd_src = open(argv[optind], O_RDONLY);
	if (fd_src < 0) {
		perror("opening src");
		return 1;
	}

	sizeblocks = lseek(fd_src, 0, SEEK_END);
	if (sizeblocks < 0) {
		perror("lseek");
		return 1;
	}
	sizeblocks = (sizeblocks + block_size - 1) / block_size;

	fd_hashmap = open(argv[optind + 1], O_CREAT | O_RDWR, 0666);
	if (fd_hashmap < 0) {
		perror("opening hashmap");
		return 1;
	}

	hashmap = malloc(sizeblocks * hash_size);
	if (hashmap == NULL) {
		fprintf(stderr, "out of memory allocating hash map\n");
		return 1;
	}
	memset(hashmap, 0, sizeblocks * hash_size);

	if (read(fd_hashmap, hashmap, sizeblocks * hash_size) == 0) {
		free(hashmap);
		hashmap = NULL;
	}

	fd_off = 0;

	if (hashmap == NULL)
		fprintf(stderr, "creating hashmap... ");
	else
		fprintf(stderr, "updating hashmap... ");

	run_threads(hash_thread, NULL);

	fprintf(stderr, "done               \n");

	close(fd_hashmap);
	close(fd_src);

	return 0;
}
