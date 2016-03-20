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
static uint8_t *srchashmap;
static int fd_dst;
static int fd_dsthashmap;
static uint8_t *dsthashmap;
static int loop;
static int max_iterations = 10;
static off_t fd_off;
static int again;

static void *copy_thread_no_hashmap(void *_me)
{
	struct worker_thread *me = _me;

	while (1) {
		uint8_t buf[block_size];
		uint8_t hash[hash_size];
		off_t off;
		int ret;

		xsem_wait(&me->sem0);

		off = fd_off;
		if (off == sizeblocks) {
			xsem_post(&me->next->sem0);
			break;
		}

		fd_off++;

		posix_fadvise(fd_src, off * block_size, 4 * block_size,
				POSIX_FADV_WILLNEED);

		ret = xpread(fd_src, buf, block_size, off * block_size);

		xsem_post(&me->next->sem0);

		if (ret < block_size && off != sizeblocks - 1) {
			fprintf(stderr, "short read\n");
			break;
		}

		gcry_md_hash_buffer(hash_algo, hash, buf, ret);

		xsem_wait(&me->sem1);

		if (memcmp(dsthashmap + off * hash_size, hash, hash_size)) {
			xpwrite(fd_dst, buf, ret, off * block_size);
			xpwrite(fd_dsthashmap, hash,
				hash_size, off * hash_size);
			memcpy(dsthashmap + off * hash_size, hash, hash_size);

			fprintf(stderr, "%Ld ", (long long)off);
			progress_reported();

			again = 1;
		} else if (should_report_progress()) {
			char str[256];

			ret = sprintf(str, "%Ld/%Ld", (long long)off,
				      (long long)sizeblocks);
			memset(str + ret, '\b', ret);
			str[2 * ret] = 0;

			fputs(str, stderr);
		}

		xsem_post(&me->next->sem1);
	}

	return NULL;
}

static void *copy_thread_hashmap(void *_me)
{
	struct worker_thread *me = _me;

	while (1) {
		uint8_t buf[block_size];
		uint8_t hash[hash_size];
		off_t off;
		int ret;

		xsem_wait(&me->sem0);

		for (off = fd_off; off < sizeblocks; off++) {
			if (memcmp(srchashmap + off * hash_size,
				   dsthashmap + off * hash_size, hash_size)) {
				break;
			}
		}

		if (off == sizeblocks) {
			fd_off = sizeblocks;
			xsem_post(&me->next->sem0);
			break;
		}

		if (should_report_progress()) {
			char str[256];
			int ret;

			ret = sprintf(str, "%Ld/%Ld", (long long)off,
				      (long long)sizeblocks);
			memset(str + ret, '\b', ret);
			str[2 * ret] = 0;

			fputs(str, stderr);
		}

		ret = xpread(fd_src, buf, block_size, off * block_size);

		fd_off = off + 1;

		xsem_post(&me->next->sem0);

		if (ret < block_size && off != sizeblocks - 1) {
			fprintf(stderr, "short read\n");
			break;
		}

		gcry_md_hash_buffer(hash_algo, hash, buf, ret);

		if (memcmp(hash, srchashmap + off * hash_size, hash_size)) {
			fprintf(stderr, "warning: source image inconsistent "
					"with its hashmap at block %Ld\n",
				(long long)off);
		}

		xsem_wait(&me->sem1);

		xpwrite(fd_dst, buf, ret, off * block_size);

		memcpy(dsthashmap + off * hash_size, hash, hash_size);
		xpwrite(fd_dsthashmap, hash, hash_size, off * hash_size);

		xsem_post(&me->next->sem1);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ "max-iter", required_argument, 0, 'i' },
		{ "loop", no_argument, 0, 'l' },
		{ 0, 0, 0, 0 },
	};
	int i;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	while (1) {
		int c;

		c = getopt_long(argc, argv, "b:h:i:l", long_options, NULL);
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

		case 'i':
			if (sscanf(optarg, "%i", &max_iterations) != 1) {
				fprintf(stderr, "cannot parse iteration "
						"count: %s\n", optarg);
				return 1;
			}

			break;

		case 'l':
			loop = 1;
			break;

		case '?':
			return 1;

		default:
			abort();
		}
	}

	if (optind + 4 != argc) {
		fprintf(stderr, "%s: [opts] <src> <srchashmap> <dst> "
				"<dsthashmap>\n", argv[0]);
		fprintf(stderr, " -b, --block-size=SIZE    hash block size\n");
		fprintf(stderr, " -h, --hash-algo=ALGO     hash algorithm\n");
		fprintf(stderr, " -i, --max-iter=ITER      maximum number of "
				"iterations\n");
		fprintf(stderr, " -l, --loop               create consistent "
				"image copy\n");
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

	if (strcmp(argv[optind + 1], "-")) {
		int fd_srchashmap;

		if (loop) {
			fprintf(stderr, "consistent image copy requested, "
					"but source hashmap specified\n");
			return 1;
		}

		fd_srchashmap = open(argv[optind + 1], O_RDONLY);
		if (fd_srchashmap < 0) {
			perror("opening srchashmap");
			return 1;
		}

		srchashmap = malloc(sizeblocks * hash_size);
		if (srchashmap == NULL) {
			fprintf(stderr, "out of memory allocating hash map\n");
			return 1;
		}

		if (read(fd_srchashmap, srchashmap, sizeblocks * hash_size)
		    != sizeblocks * hash_size) {
			fprintf(stderr, "error reading hash map\n");
			return 1;
		}

		close(fd_srchashmap);
	} else {
		srchashmap = NULL;
	}

	fd_dst = open(argv[optind + 2], O_CREAT | O_RDWR, 0666);
	if (fd_dst < 0) {
		perror("opening dst");
		return 1;
	}

	fd_dsthashmap = open(argv[optind + 3], O_CREAT | O_RDWR, 0666);
	if (fd_dsthashmap < 0) {
		perror("opening dsthashmap");
		return 1;
	}

	dsthashmap = malloc(sizeblocks * hash_size);
	if (dsthashmap == NULL) {
		fprintf(stderr, "out of memory allocating hash map\n");
		return 1;
	}

	if (read(fd_dsthashmap, dsthashmap, sizeblocks * hash_size)
	    != sizeblocks * hash_size) {
		fprintf(stderr, "error reading hash map\n");
		return 1;
	}

	if (loop) {
		for (i = 0; i < max_iterations; i++) {
			fd_off = 0;
			again = 0;

			fprintf(stderr, "scanning for differences... ");
			run_threads(copy_thread_no_hashmap);
			fprintf(stderr, "done               \n");

			if (!again)
				break;

			if (i == max_iterations - 1) {
				fprintf(stderr, "maximum iteration count "
						"reached, bailing out\n");
			} else {
				fprintf(stderr, "repeating scanning due to "
						"differences\n");
			}
		}
	} else {
		fd_off = 0;

		if (srchashmap == NULL) {
			fprintf(stderr, "scanning for differences... ");
			run_threads(copy_thread_no_hashmap);
		} else {
			fprintf(stderr, "copying differences... ");
			run_threads(copy_thread_hashmap);
		}
		fprintf(stderr, "done               \n");
	}

	fprintf(stderr, "flushing buffers... ");
	close(fd_src);
	close(fd_dst);
	close(fd_dsthashmap);
	fprintf(stderr, "done\n");

	return 0;
}
