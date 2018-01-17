/*
 * replika, a set of tools for dealing with hashmapped disk images
 * Copyright (C) 2017, 2018 Lennert Buytenhek
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
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <linux/fs.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "common.h"
#include "dedup.h"

#ifndef FIDEDUPERANGE
#define FIDEDUPERANGE	_IOWR(0x94, 54, struct file_dedupe_range)

#define FILE_DEDUPE_RANGE_SAME		0
#define FILE_DEDUPE_RANGE_DIFFERS	1

struct file_dedupe_range_info {
	int64_t		dest_fd;
	uint64_t	dest_offset;
	uint64_t	bytes_deduped;
	int32_t		status;
	uint32_t	reserved;
};

struct file_dedupe_range {
	uint64_t	src_offset;
	uint64_t	src_length;
	uint16_t	dest_count;
	uint16_t	reserved1;
	uint32_t	reserved2;
	struct file_dedupe_range_info	info[0];
};
#endif

struct dedup_op
{
	struct file	*dst;
	off_t		dstblock;
	struct file	*src;
	off_t		srcblock;
};

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int dry_run;
static int verbose;

static struct dedup_op *dedup_ops;
static int dedup_ops_alloc;
static int dedup_ops_used;
static int dedup_index;

static void queue_dedup_op(struct file *dst, off_t dstblock,
			   struct file *src, off_t srcblock)
{
	struct dedup_op *op;

	if (dedup_ops_alloc == dedup_ops_used) {
		int toalloc;

		if (dedup_ops_alloc)
			toalloc = 2 * dedup_ops_alloc;
		else
			toalloc = 1024;

		dedup_ops = realloc(dedup_ops, toalloc * sizeof(dedup_ops[0]));
		if (dedup_ops == NULL)
			abort();

		dedup_ops_alloc = toalloc;
	}

	op = dedup_ops + dedup_ops_used;
	op->dst = dst;
	op->dstblock = dstblock;
	op->src = src;
	op->srcblock = srcblock;

	dedup_ops_used++;
}

static void
dedup_file_range(int dstfd, off_t dstblock, int srcfd, off_t srcblock)
{
	off_t off;

	off = 0;
	while (off < block_size) {
		struct {
			struct file_dedupe_range r;
			struct file_dedupe_range_info ri;
		} x;

		x.r.src_offset = srcblock * block_size + off;
		x.r.src_length = block_size - off;
		x.r.dest_count = 1;
		x.r.reserved1 = 0;
		x.r.reserved2 = 0;
		x.ri.dest_fd = dstfd;
		x.ri.dest_offset = dstblock * block_size + off;
		x.ri.bytes_deduped = 0;
		x.ri.status = 0;
		x.ri.reserved = 0;

		if (ioctl(srcfd, FIDEDUPERANGE, &x) < 0) {
			perror("ioctl");
			break;
		}

		if (x.ri.status == FILE_DEDUPE_RANGE_DIFFERS) {
			fprintf(stderr, "welp, data differs\n");
			break;
		}

		if (x.ri.status != FILE_DEDUPE_RANGE_SAME) {
			fprintf(stderr, "FIDEDUPERANGE: %s\n",
				strerror(-x.ri.status));
			break;
		}

		if (x.ri.bytes_deduped == 0) {
			fprintf(stderr, "welp, deduped zero bytes?\n");
			break;
		}

		off += x.ri.bytes_deduped;
	}
}

static void *dedup_thread(void *_me)
{
	struct worker_thread *me = _me;

	xsem_wait(&me->sem0);

	while (dedup_index < dedup_ops_used) {
		struct dedup_op *op;

		op = dedup_ops + dedup_index;
		dedup_index++;

		if (dry_run || (verbose && should_report_progress())) {
			printf("[%d/%d] %s %Ld => %s %Ld\n",
			       dedup_index, dedup_ops_used,
			       op->src->name, (long long)op->srcblock,
			       op->dst->name, (long long)op->dstblock);
		}

		if (dry_run)
			continue;

		posix_fadvise(op->src->fd, op->srcblock * block_size,
			      16 * block_size, POSIX_FADV_WILLNEED);

		posix_fadvise(op->dst->fd, op->dstblock * block_size,
			      16 * block_size, POSIX_FADV_WILLNEED);

		xsem_post(&me->next->sem0);

		dedup_file_range(op->dst->fd, op->dstblock,
				 op->src->fd, op->srcblock);

		xsem_wait(&me->sem0);
	}

	xsem_post(&me->next->sem0);

	return NULL;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{ "block-size", required_argument, 0, 'b' },
		{ "dry-run", no_argument, 0, 'd' },
		{ "hash-algo", required_argument, 0, 'h' },
		{ "hash-algorithm", required_argument, 0, 'h' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0, 0, 0, 0 },
	};
	int num;
	int i;

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

		case 'd':
			dry_run = 1;
			break;

		case 'h':
			hash_algo = gcry_md_map_name(optarg);
			if (hash_algo == 0) {
				fprintf(stderr, "unknown hash algorithm "
						"name: %s\n", optarg);
				return 1;
			}

			break;

		case 'v':
			verbose = 1;
			break;

		case '?':
			return 1;

		default:
			abort();
		}
	}

	num = argc - optind;
	if (num < 2 || num & 1) {
		fprintf(stderr, "%s: [opts] <a.img> <a.map> [...]\n", argv[0]);
		fprintf(stderr, " -b, --block-size=SIZE    hash block size\n");
		fprintf(stderr, " -d, --dry-run            don't dedup\n");
		fprintf(stderr, " -h, --hash-algo=ALGO     hash algorithm\n");
		fprintf(stderr, " -v, --verbose            more output\n");
		return 1;
	}

	num /= 2;

	dedup_scan_init(block_size, gcry_md_get_algo_dlen(hash_algo));

	for (i = 0; i < num; i++) {
		const char *imgfile = argv[optind + 2 * i];
		const char *mapfile = argv[optind + 2 * i + 1];

		if (verbose)
			printf("scanning file %s\n", imgfile);
		dedup_scan_file(imgfile, mapfile, i);
	}

	dedup_scan_ops(queue_dedup_op);

	if (dedup_ops_used) {
		run_threads(dedup_thread, NULL);
		free(dedup_ops);
	}

	dedup_scan_deinit();

	return 0;
}
