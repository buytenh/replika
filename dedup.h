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

#ifndef __DEDUP_H
#define __DEDUP_H

#include <iv_avl.h>
#include <iv_list.h>

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

void dedup_scan_init(int block_size, int hash_size);
void dedup_scan_file(const char *imgfile, const char *mapfile, int index);
void dedup_scan_ops(void (*dedup_op)(struct file *dst, off_t dstblock,
				     struct file *src, off_t srcblock));
void dedup_scan_deinit(void);


#endif
