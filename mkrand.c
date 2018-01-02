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
#include <arpa/inet.h>
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
static int cipher_algo = GCRY_CIPHER_AES128;
static int key_size;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;
static int fd_dst;
static int fd_hashmap;
static uint8_t key[64];
static off_t sizeblocks;
static off_t fd_off;

static void *mkrand_thread(void *_me)
{
	struct worker_thread *me = _me;
	gcry_cipher_hd_t hd;

	xsem_wait(&me->sem0);

	/*
	 * libgcrypt 1.6.3 segfaults if gcry_cipher_open() calls
	 * are not strictly serialised.
	 */
	if (gcry_cipher_open(&hd, cipher_algo, GCRY_CIPHER_MODE_ECB, 0)) {
		fprintf(stderr, "error opening cipher\n");
		exit(1);
	}

	if (gcry_cipher_setkey(hd, key, key_size)) {
		fprintf(stderr, "error setting key\n");
		exit(1);
	}

	while (fd_off < sizeblocks) {
		uint8_t buf[block_size];
		uint8_t hash[hash_size];
		off_t off;
		uint64_t ctr;
		uint32_t *ptr;
		int i;

		off = fd_off++;

		xsem_post(&me->next->sem0);

		ctr = off * (block_size / 8);
		ptr = (uint32_t *)buf;

		for (i = 0; i < block_size; i += 8) {
			*ptr++ = htonl(ctr >> 32);
			*ptr++ = htonl(ctr & 0xffffffff);
			ctr++;
		}

		if (gcry_cipher_encrypt(hd, buf, block_size, buf, block_size)) {
			fprintf(stderr, "error encrypting block\n");
			exit(1);
		}

		gcry_md_hash_buffer(hash_algo, hash, buf, block_size);

		xsem_wait(&me->sem0);

		xpwrite(fd_dst, buf, block_size, off * block_size);
		xpwrite(fd_hashmap, hash, hash_size, off * hash_size);

		if (should_report_progress()) {
			char str[256];
			int ret;

			ret = sprintf(str, "%Ld/%Ld", (long long)off,
				      (long long)sizeblocks);
			memset(str + ret, '\b', ret);
			str[2 * ret] = 0;

			fputs(str, stderr);
		}
	}

	xsem_post(&me->next->sem0);

	gcry_cipher_close(hd);

	return NULL;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "cipher-algo", required_argument, 0, 'c' },
		{ "cipher-algorithm", required_argument, 0, 'c' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int fd_key;
	long long lltemp;
	int ret;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	while (1) {
		int c;

		c = getopt_long(argc, argv, "b:c:h:", long_options, NULL);
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

		case 'c':
			cipher_algo = gcry_cipher_map_name(optarg);
			if (cipher_algo == 0) {
				fprintf(stderr, "unknown cipher algorithm "
						"name: %s\n", optarg);
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

	if (optind + 3 > argc) {
		fprintf(stderr, "%s: [opts] <image> <hashmap> <keyfile> "
				"[size] [offset]\n", argv[0]);
		fprintf(stderr, " -b, --block-size=SIZE    hash block size\n");
		fprintf(stderr, " -c, --cipher-algo=ALGO   cipher algorithm\n");
		fprintf(stderr, " -h, --hash-algo=ALGO     hash algorithm\n");
		return 1;
	}

	key_size = gcry_cipher_get_algo_keylen(cipher_algo);
	hash_size = gcry_md_get_algo_dlen(hash_algo);

	fd_dst = open(argv[optind], O_CREAT | O_WRONLY, 0666);
	if (fd_dst < 0) {
		perror("opening dst");
		return 1;
	}

	fd_hashmap = open(argv[optind + 1], O_CREAT | O_RDWR, 0666);
	if (fd_hashmap < 0) {
		perror("opening hashmap");
		return 1;
	}

	fd_key = open(argv[optind + 2], O_RDONLY);
	if (fd_key < 0) {
		perror("opening keyfile");
		return 1;
	}

	if (read(fd_key, key, key_size) != key_size) {
		fprintf(stderr, "error reading %d bytes of key material\n",
			key_size);
		return 1;
	}

	close(fd_key);

	if (optind + 3 < argc) {
		if (sscanf(argv[optind + 3], "%Li", &lltemp) != 1) {
			fprintf(stderr, "unable to parse size: %s\n",
				argv[optind + 3]);
			return 1;
		}

		sizeblocks = (1048576 * lltemp) / block_size;
	} else {
		lltemp = lseek(fd_dst, 0, SEEK_END);
		if (lltemp < 0) {
			perror("lseek");
			return 1;
		}

		sizeblocks = lltemp / block_size;
	}

	if (optind + 4 < argc) {
		if (sscanf(argv[optind + 4], "%Li", &lltemp) != 1) {
			fprintf(stderr, "unable to parse offset: %s\n",
				argv[optind + 4]);
			return 1;
		}

		fd_off = (1048576 * lltemp) / block_size;
	} else {
		fd_off = 0;
	}

	fprintf(stderr, "writing random data... ");
	ret = posix_fallocate(fd_hashmap, 0, sizeblocks * hash_size);
	if (ret) {
		fprintf(stderr, "posix_fallocate(hashmap): %s\n",
			strerror(ret));
	}
	run_threads(mkrand_thread, NULL);
	fprintf(stderr, "done               \n");

	fprintf(stderr, "flushing buffers... ");
	close(fd_dst);
	close(fd_hashmap);
	fprintf(stderr, "done\n");

	return 0;
}
