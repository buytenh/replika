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
#include <iv_avl.h>
#include <iv_list.h>
#include <linux/fs.h>
#include <stdint.h>
#include <unistd.h>
#include "dedup.h"
#include "extents.h"

struct block_hash
{
	struct iv_avl_node	an;
	struct iv_avl_tree	refs;
	uint8_t			hash[0];
};

static int block_size = 1048576;
static int hash_size;

static struct iv_list_head files;
static struct iv_avl_tree block_hashes;

static int compare_block_hashes(const struct iv_avl_node *_a,
				const struct iv_avl_node *_b)
{
	const struct block_hash *a = iv_container_of(_a, struct block_hash, an);
	const struct block_hash *b = iv_container_of(_b, struct block_hash, an);

	return memcmp(a->hash, b->hash, hash_size);
}

void dedup_scan_init(int _block_size, int _hash_size)
{
	block_size = _block_size;
	hash_size = _hash_size;

	INIT_IV_LIST_HEAD(&files);
	INIT_IV_AVL_TREE(&block_hashes, compare_block_hashes);
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

void dedup_scan_file(const char *imgfile, const char *mapfile, int index)
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

void dedup_scan_ops(void (*dedup_op)(struct file *dst, off_t dstblock,
				     struct file *src, off_t srcblock))
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
					dedup_op(dst->f, dstblock,
						 src->f, srcblock);
				}
			}
		}
	}
}

void dedup_scan_deinit(void)
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
}
