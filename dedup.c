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
#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <getopt.h>
#include <iv_avl.h>
#include <iv_list.h>
#include <linux/fs.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "common.h"
#include "extents.h"

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

struct block_hash
{
	struct iv_avl_node	an;
	struct iv_avl_tree	refs;
	uint8_t			hash[0];
};

struct hashref
{
	struct iv_avl_node	an;
	struct file		*f;
	struct block_hash	*bh;
};

struct file
{
	struct iv_list_head	list;
	int			readonly;
	int			index;
	const char		*name;
	int			fd;
	uint64_t		blocks;
	struct iv_avl_tree	extent_tree;
	struct hashref		refs[0];
};

struct dedup_op
{
	struct file		*dst;
	off_t			dstblock;
	struct file		*src;
	off_t			srcblock;
};

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;
static int dry_run;
static int verbose;
static struct iv_list_head files;
static struct iv_avl_tree block_hashes;
static struct dedup_op *dedup_ops;
static int dedup_ops_alloc;
static int dedup_ops_used;

static int compare_block_hashes(const struct iv_avl_node *_a,
				const struct iv_avl_node *_b)
{
	const struct block_hash *a = iv_container_of(_a, struct block_hash, an);
	const struct block_hash *b = iv_container_of(_b, struct block_hash, an);

	return memcmp(a->hash, b->hash, hash_size);
}

static struct block_hash *find_block_hash(uint8_t *hash)
{
	struct iv_avl_node *an;

	an = block_hashes.root;
	while (an != NULL) {
		struct block_hash *bh;
		int ret;

		bh = iv_container_of(an, struct block_hash, an);

		ret = memcmp(hash, bh->hash, hash_size);
		if (ret == 0)
			return bh;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static int
compare_hashrefs(const struct iv_avl_node *_a, const struct iv_avl_node *_b)
{
	const struct hashref *a = iv_container_of(_a, struct hashref, an);
	const struct hashref *b = iv_container_of(_b, struct hashref, an);

	if (a->f->readonly > b->f->readonly)
		return -1;
	if (a->f->readonly < b->f->readonly)
		return 1;

	if (a->f->index > b->f->index)
		return -1;
	if (a->f->index < b->f->index)
		return 1;

	if (a - a->f->refs < b - b->f->refs)
		return -1;
	if (a - a->f->refs > b - b->f->refs)
		return 1;

	return 0;
}

static struct block_hash *get_block_hash(uint8_t *hash)
{
	struct block_hash *bh;

	bh = find_block_hash(hash);
	if (bh == NULL) {
		bh = malloc(sizeof(*bh) + hash_size);
		if (bh == NULL)
			abort();

		INIT_IV_AVL_TREE(&bh->refs, compare_hashrefs);
		memcpy(bh->hash, hash, hash_size);
		iv_avl_tree_insert(&block_hashes, &bh->an);
	}

	return bh;
}

static void add_file(const char *imgfile, const char *mapfile, int index)
{
	int readonly;
	int imgfd;
	off_t imgsize;
	off_t sizeblocks;
	FILE *mapf;
	off_t mapsize;
	char mapbuf[1048576];
	struct file *f;
	uint8_t dirty_hash[hash_size];
	off_t i;

	if (verbose)
		printf("scanning file %s\n", imgfile);

	readonly = 0;

	imgfd = open(imgfile, O_RDWR);
	if (imgfd < 0 && (errno == EACCES || errno == EPERM)) {
		readonly = 1;
		imgfd = open(imgfile, O_RDONLY);
	}

	if (imgfd < 0) {
		fprintf(stderr, "error opening %s: %s\n",
			imgfile, strerror(errno));
		exit(1);
	}

	imgsize = lseek(imgfd, 0, SEEK_END);
	if (imgsize < 0) {
		perror("lseek");
		exit(1);
	}

	sizeblocks = (imgsize + block_size - 1) / block_size;
	if (sizeblocks == 0) {
		close(imgfd);
		return;
	}

	mapf = fopen(mapfile, "r");
	if (mapf == NULL) {
		fprintf(stderr, "error opening %s: %s\n",
			mapfile, strerror(errno));
		exit(1);
	}

	if (fseeko(mapf, 0, SEEK_END) < 0) {
		perror("fseeko");
		exit(1);
	}

	mapsize = ftello(mapf);
	if (mapsize != sizeblocks * hash_size) {
		fprintf(stderr, "size of %s (%Ld) does not match size of "
				"%s (%Ld)\n", imgfile, (long long)imgsize,
			mapfile, (long long)mapsize);
		exit(1);
	}

	if (fseeko(mapf, 0, SEEK_SET) < 0) {
		perror("fseeko");
		exit(1);
	}

	setbuffer(mapf, mapbuf, sizeof(mapbuf));

	f = malloc(sizeof(*f) + sizeblocks * sizeof(struct hashref));
	if (f == NULL)
		abort();

	iv_list_add(&f->list, &files);
	f->readonly = readonly;
	f->index = index;
	f->name = imgfile;
	f->fd = imgfd;
	f->blocks = sizeblocks;

	if (extent_tree_build(&f->extent_tree, imgfd) < 0) {
		fprintf(stderr, "error building extent tree for %s\n", imgfile);
		exit(1);
	}

	memset(dirty_hash, 0, sizeof(dirty_hash));

	for (i = 0; i < sizeblocks; i++) {
		uint8_t hash[hash_size];
		struct block_hash *bh;
		struct hashref *hr;

		if (fread(hash, hash_size, 1, mapf) != 1) {
			fprintf(stderr, "error reading from map file\n");
			exit(1);
		}

		if (memcmp(hash, dirty_hash, hash_size) == 0)
			continue;

		bh = get_block_hash(hash);

		hr = f->refs + i;
		hr->f = f;
		hr->bh = bh;
		iv_avl_tree_insert(&bh->refs, &hr->an);
	}

	fclose(mapf);
}

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

static void build_dedup_ops(void)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &files) {
		struct file *f;
		int i;

		f = iv_container_of(lh, struct file, list);

		for (i = 0; i < f->blocks; i++) {
			struct iv_avl_node *min;
			struct hashref *src;
			off_t srcblock;
			struct iv_avl_node *an;

			min = iv_avl_tree_min(&f->refs[i].bh->refs);
			if (min == NULL)
				continue;

			src = iv_container_of(min, struct hashref, an);
			if (f != src->f)
				continue;

			srcblock = src - src->f->refs;

			an = iv_avl_tree_next(min);
			while (an != NULL) {
				struct hashref *dst;
				off_t dstblock;

				dst = iv_container_of(an, struct hashref, an);
				an = iv_avl_tree_next(an);

				if (dst->f->readonly)
					continue;

				dstblock = dst - dst->f->refs;
				if (extent_tree_diff(&src->f->extent_tree,
						     srcblock * block_size,
						     &dst->f->extent_tree,
						     dstblock * block_size,
						     block_size)) {
					queue_dedup_op(dst->f, dstblock,
						       src->f, srcblock);
				}
			}
		}
	}
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

static int
dedup_block_hash(struct iv_avl_node *min, int dedup_index, int dedup_count)
{
	struct hashref *src;
	off_t srcblock;
	int count;
	struct iv_avl_node *an;

	src = iv_container_of(min, struct hashref, an);
	srcblock = src - src->f->refs;

	count = 0;

	an = iv_avl_tree_next(min);
	while (an != NULL) {
		struct hashref *dst;
		off_t dstblock;

		dst = iv_container_of(an, struct hashref, an);
		an = iv_avl_tree_next(an);

		if (dst->f->readonly)
			continue;

		dstblock = dst - dst->f->refs;

		if (!extent_tree_diff(&src->f->extent_tree,
				      srcblock * block_size,
				      &dst->f->extent_tree,
				      dstblock * block_size, block_size)) {
			continue;
		}

		if (dedup_count &&
		    (dry_run || (verbose && should_report_progress()))) {
			printf("[%d/%d] %s %Ld => %s %Ld\n",
			       dedup_index, dedup_count,
			       src->f->name, (long long)srcblock,
			       dst->f->name, (long long)dstblock);
		}

		dedup_index++;
		count++;

		if (dry_run || dedup_count == 0)
			continue;

		posix_fadvise(src->f->fd, srcblock * block_size,
			      16 * block_size, POSIX_FADV_WILLNEED);

		posix_fadvise(dst->f->fd, dstblock * block_size,
			      16 * block_size, POSIX_FADV_WILLNEED);

		dedup_file_range(dst->f->fd, dstblock, src->f->fd, srcblock);
	}

	return count;
}

struct dedup_state
{
	struct file	*f;
	off_t		block;
	int		dedup_index;
	int		dedup_count;
};

static void *dedup_thread(void *_me)
{
	struct worker_thread *me = _me;
	struct dedup_state *ds = me->cookie;

	xsem_wait(&me->sem0);

	while (1) {
		struct file *f;
		off_t block;
		struct block_hash *bh;
		struct iv_avl_node *an;

		f = ds->f;
		if (f == NULL)
			break;

		block = ds->block;
		if (block == 0 && (dry_run || verbose))
			printf("deduping blocks from %s\n", f->name);

		ds->block++;
		if (ds->block == f->blocks) {
			struct iv_list_head *lh;

			lh = f->list.next;
			if (lh != &files)
				ds->f = iv_container_of(lh, struct file, list);
			else
				ds->f = NULL;

			ds->block = 0;
		}

		bh = f->refs[block].bh;

		an = iv_avl_tree_min(&bh->refs);
		if (an != NULL) {
			int count;
			struct iv_avl_node *an2;

			bh->refs.root = NULL;

			count = dedup_block_hash(an, 0, 0);

			an2 = iv_avl_tree_next(an);
			if (an2 != NULL) {
				int index;

				index = ds->dedup_index;
				ds->dedup_index += count;

				xsem_post(&me->next->sem0);
				dedup_block_hash(an, index, ds->dedup_count);
				xsem_wait(&me->sem0);
			}
		}
	}

	xsem_post(&me->next->sem0);

	return NULL;
}

static void scandups(void)
{
	build_dedup_ops();
	if (dedup_ops_used) {
		struct dedup_state ds;

		ds.f = iv_container_of(files.next, struct file, list);
		ds.block = 0;
		ds.dedup_index = 1;
		ds.dedup_count = dedup_ops_used;
		run_threads(dedup_thread, &ds);
	}
}

static void destroy(void)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;
	struct iv_avl_node *an;
	struct iv_avl_node *an2;

	iv_list_for_each_safe (lh, lh2, &files) {
		struct file *f;

		f = iv_container_of(lh, struct file, list);
		iv_list_del(&f->list);
		extent_tree_free(&f->extent_tree);
		free(f);
	}

	iv_avl_tree_for_each_safe (an, an2, &block_hashes) {
		struct block_hash *bh;

		bh = iv_container_of(an, struct block_hash, an);
		iv_avl_tree_delete(&block_hashes, &bh->an);
		free(bh);
	}

	free(dedup_ops);
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

	INIT_IV_LIST_HEAD(&files);
	INIT_IV_AVL_TREE(&block_hashes, compare_block_hashes);

	hash_size = gcry_md_get_algo_dlen(hash_algo);

	for (i = 0; i < num; i++)
		add_file(argv[optind + 2 * i], argv[optind + 2 * i + 1], i);

	scandups();

	destroy();

	return 0;
}
