/*
 * replika, a set of tools for dealing with hashmapped disk images
 * Copyright (C) 2019 Lennert Buytenhek
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
#include <iv_avl.h>
#include <iv_list.h>
#include <string.h>

struct key {
	struct iv_avl_node	an;
	uint8_t			key[0];
};

static int key_size;
static struct iv_avl_tree keys;
static int key_count;
static int unique_keys;

static int compare_keys(const struct iv_avl_node *_a,
			const struct iv_avl_node *_b)
{
	const struct key *a;
	const struct key *b;

	a = iv_container_of(_a, struct key, an);
	b = iv_container_of(_b, struct key, an);

	return memcmp(a->key, b->key, key_size);
}

static struct key *find_key(uint8_t *key)
{
	struct iv_avl_node *an;

	an = keys.root;
	while (an != NULL) {
		struct key *k;
		int ret;

		k = iv_container_of(an, struct key, an);

		ret = memcmp(key, k->key, key_size);
		if (ret == 0)
			return k;

		if (ret < 0)
			an = an->left;
		else
			an = an->right;
	}

	return NULL;
}

static void scan(FILE *fp)
{
	while (1) {
		uint8_t key[key_size];
		int ret;
		struct key *k;

		ret = fread(key, 1, key_size, fp);
		if (ret != key_size)
			break;

		key_count++;

		k = find_key(key);
		if (k == NULL) {
			k = malloc(sizeof(*k) + key_size);
			if (k == NULL)
				exit(EXIT_FAILURE);

			memcpy(k->key, key, key_size);
			iv_avl_tree_insert(&keys, &k->an);

			unique_keys++;
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "syntax: %s <key_size> [mapfile]*\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (sscanf(argv[1], "%d", &key_size) != 1) {
		fprintf(stderr, "can't parse key size %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	INIT_IV_AVL_TREE(&keys, compare_keys);

	if (argc == 2) {
		scan(stdin);
	} else {
		int i;

		for (i = 2; i < argc; i++) {
			FILE *fp;

			fp = fopen(argv[i], "r");
			if (fp == NULL) {
				fprintf(stderr, "can't open %s\n", argv[i]);
				continue;
			}

			scan(fp);
			fclose(fp);
		}
	}

	printf("%d\t%d\n", unique_keys, key_count);

	return 0;
}
