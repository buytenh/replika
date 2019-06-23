/*
 * replika, a set of tools for dealing with hashmapped disk images
 * Copyright (C) 2017, 2018, 2019 Lennert Buytenhek
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

#define PACKAGE_VERSION "0.1"

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <gcrypt.h>
#include <limits.h>
#include <linux/falloc.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <values.h>
#include "common.h"

#define DIV_ROUND_UP(x, y)	(((x) + (y) - 1) / (y))

#define BG_SIZE		64

struct block_group
{
	pthread_rwlock_t	lock;
	uint8_t			dirty[BG_SIZE / BITSPERBYTE];
};

struct efes_file_info
{
	int		imgfd;
	int		writable;
	uint64_t	file_size;
	uint64_t	numblocks;
	int		mapfd;
	struct block_group	bg[0];
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int block_size = 1048576;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;

static int backing_dir_fd;
static pthread_mutex_t readdir_lock;

static int efes_getattr(const char *path, struct stat *buf)
{
	int ret;

	if (path[0] != '/') {
		fprintf(stderr, "getattr called with [%s]\n", path);
		return -ENOENT;
	}

	ret = fstatat(backing_dir_fd, path + 1, buf,
		      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (ret < 0)
		return -errno;

	if ((buf->st_mode & S_IFMT) == S_IFREG) {
		int len;

		len = strlen(path);
		if (len < 6 || strcmp(path + len - 4, ".img"))
			return -ENOENT;
	}

	return 0;
}

static void dirty_set(struct efes_file_info *fh, uint64_t block)
{
	struct block_group *bg;
	unsigned int bgoff;
	unsigned int bgbyte;
	unsigned int bgmask;

	bg = &fh->bg[block / BG_SIZE];
	bgoff = block % BG_SIZE;
	bgbyte = bgoff / BITSPERBYTE;
	bgmask = 1 << (bgoff % BITSPERBYTE);

	bg->dirty[bgbyte] |= bgmask;
}

static void dirty_clear(struct efes_file_info *fh, uint64_t block)
{
	struct block_group *bg;
	unsigned int bgoff;
	unsigned int bgbyte;
	unsigned int bgmask;

	bg = &fh->bg[block / BG_SIZE];
	bgoff = block % BG_SIZE;
	bgbyte = bgoff / BITSPERBYTE;
	bgmask = 1 << (bgoff % BITSPERBYTE);

	bg->dirty[bgbyte] &= ~bgmask;
}

static int efes_open(const char *path, struct fuse_file_info *fi)
{
	int len;
	int writable;
	int imgfd;
	struct stat buf;
	int ret;
	int mapfd;
	uint64_t numblocks;
	uint64_t numbg;
	struct efes_file_info *fh;

	if (path[0] != '/') {
		fprintf(stderr, "open called with [%s]\n", path);
		return -ENOENT;
	}

	len = strlen(path);
	if (len < 6 || strcmp(path + len - 4, ".img"))
		return -ENOENT;

	writable = !((fi->flags & O_ACCMODE) == O_RDONLY);

	imgfd = openat(backing_dir_fd, path + 1, writable ? O_RDWR : O_RDONLY);
	if (imgfd < 0)
		return -errno;

	mapfd = -1;
	if (writable) {
		char mappath[len + 1];

		strcpy(mappath, path);
		strcpy(mappath + len - 4, ".map");

		mapfd = openat(backing_dir_fd, mappath + 1, O_RDWR);
		if (mapfd < 0) {
			fprintf(stderr, "efes_open: mapfile %s openat %s\n",
				mappath, strerror(errno));
			close(imgfd);
			return -EPERM;
		}
	}

	ret = fstat(imgfd, &buf);
	if (ret < 0) {
		ret = -errno;
		if (writable)
			close(mapfd);
		close(imgfd);
		return ret;
	}

	numblocks = DIV_ROUND_UP(buf.st_size, block_size);
	numbg = writable ? DIV_ROUND_UP(numblocks, BG_SIZE) : 0;

	fh = malloc(sizeof(*fh) + numbg * sizeof(fh->bg[0]));
	if (fh == NULL) {
		if (writable)
			close(mapfd);
		close(imgfd);
		return -ENOMEM;
	}

	fh->imgfd = imgfd;
	fh->writable = writable;
	fh->file_size = buf.st_size;
	fh->numblocks = numblocks;
	fh->mapfd = mapfd;
	if (writable) {
		uint8_t dirty_hash[hash_size];
		int mapfd2;
		FILE *fp;
		char mapbuf[1048576];
		uint64_t i;

		memset(dirty_hash, 0, sizeof(dirty_hash));

		mapfd2 = dup(mapfd);
		if (mapfd2 < 0) {
			perror("dup");
			if (writable)
				close(mapfd);
			close(imgfd);
			free(fh);
			return -EIO;
		}

		fp = fdopen(mapfd2, "r");
		if (fp == NULL) {
			perror("fdopen");
			close(mapfd2);
			if (writable)
				close(mapfd);
			close(imgfd);
			free(fh);
			return -EIO;
		}

		setbuffer(fp, mapbuf, sizeof(mapbuf));

		for (i = 0; i < numbg; i++)
			pthread_rwlock_init(&fh->bg[i].lock, NULL);

		for (i = 0; i < numblocks; i++) {
			uint8_t hash[hash_size];
			int ret;

			ret = fread(hash, hash_size, 1, fp);
			if (ret < 1)
				fseek(fp, (i + 1) * block_size, SEEK_SET);

			if (ret < 1 || !memcmp(hash, dirty_hash, hash_size))
				dirty_set(fh, i);
			else
				dirty_clear(fh, i);
		}

		fclose(fp);
	}

	fi->fh = (uint64_t)fh;

	return 0;
}

static int efes_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;

	return pread(fh->imgfd, buf, size, offset);
}

static int dirty_test(struct efes_file_info *fh, uint64_t block)
{
	struct block_group *bg;
	unsigned int bgoff;
	unsigned int bgbyte;
	unsigned int bgmask;

	bg = &fh->bg[block / BG_SIZE];
	bgoff = block % BG_SIZE;
	bgbyte = bgoff / BITSPERBYTE;
	bgmask = 1 << (bgoff % BITSPERBYTE);

	return !!(bg->dirty[bgbyte] & bgmask);
}

static void make_dirty_for_writing(struct efes_file_info *fh, off_t block)
{
	if (!dirty_test(fh, block)) {
		uint8_t hash[hash_size];

		memset(hash, 0, hash_size);
		xpwrite(fh->mapfd, hash, hash_size, block * hash_size);

		dirty_set(fh, block);
	}
}

static int efes_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;
	off_t processed;

	if (!fh->writable)
		return -EBADF;

	if (offset >= fh->file_size)
		return -ENOSPC;

	if (size > INT_MAX)
		size = INT_MAX;

	processed = 0;
	while (processed < size) {
		size_t towrite;
		off_t block;
		struct block_group *bg;
		int ret;

		if (offset >= fh->file_size)
			break;

		towrite = size - processed;
		if (offset + towrite > fh->file_size)
			towrite = fh->file_size - offset;
		if (towrite > block_size - (offset % block_size))
			towrite = block_size - (offset % block_size);

		block = offset / block_size;
		bg = &fh->bg[block / BG_SIZE];

		pthread_rwlock_wrlock(&bg->lock);

		make_dirty_for_writing(fh, block);

		ret = pwrite(fh->imgfd, buf, towrite, offset);

		pthread_rwlock_unlock(&bg->lock);

		if (ret < 0)
			return processed ? processed : -errno;

		buf += ret;
		offset += ret;

		processed += ret;
	}

	return processed;
}

static int efes_statfs(const char *path, struct statvfs *buf)
{
	int ret;

	if (strcmp(path, "/")) {
		fprintf(stderr, "statfs called with [%s]\n", path);
		return -ENOENT;
	}

	ret = fstatvfs(backing_dir_fd, buf);
	if (ret < 0)
		return -errno;

	return 0;
}

struct commit_state
{
	struct efes_file_info	*fh;
	uint64_t		block;
	uint64_t		dirty_index;
	uint64_t		num_dirty;
};

static void *commit_thread(void *_me)
{
	struct worker_thread *me = _me;
	struct commit_state *cs = me->cookie;
	struct efes_file_info *fh = cs->fh;

	while (1) {
		off_t block;
		off_t off;
		uint8_t buf[block_size];
		int ret;
		uint8_t hash[hash_size];

		xsem_wait(&me->sem0);

		for (block = cs->block; block < fh->numblocks; block++) {
			if (dirty_test(fh, block))
				break;
		}

		if (block == fh->numblocks) {
			cs->block = fh->numblocks;
			xsem_post(&me->next->sem0);
			break;
		}

		cs->block = block + 1;
		cs->dirty_index++;

		if (should_report_progress()) {
			fprintf(stderr, "committing %Ld/%Ld (%Ld/%Ld "
					"dirty blocks)\n",
				(long long)block,
				(long long)fh->numblocks,
				(long long)cs->dirty_index,
				(long long)cs->num_dirty);
		}

		xsem_post(&me->next->sem0);

		off = block * block_size;

		ret = xpread(fh->imgfd, buf, block_size, off);
		if ((ret < block_size && block != fh->numblocks - 1) ||
		    (ret <= 0 && block == fh->numblocks - 1)) {
			fprintf(stderr, "commit_thread: short read on "
					"block %Ld\n", (long long)block);
			memset(hash, 0, hash_size);
		} else {
			xpwrite(fh->imgfd, buf, ret, off);
			gcry_md_hash_buffer(hash_algo, hash, buf, ret);
		}

		xpwrite(fh->mapfd, hash, hash_size, block * hash_size);
	}

	return NULL;
}

static int efes_release(const char *path, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;

	if (fh->writable) {
		uint64_t num_dirty;
		uint64_t i;
		uint64_t numbg;

		num_dirty = 0;
		for (i = 0; i < fh->numblocks; i++) {
			if (dirty_test(fh, i))
				num_dirty++;
		}

		if (num_dirty) {
			struct commit_state cs;

			if (stderr_is_tty()) {
				fprintf(stderr, "committing %s (%Ld dirty "
						"blocks)\n",
					path + 1, (long long)num_dirty);
			}

			cs.fh = fh;
			cs.block = 0;
			cs.dirty_index = 0;
			cs.num_dirty = num_dirty;
			run_threads(commit_thread, &cs);

			if (stderr_is_tty())
				fprintf(stderr, "commit done\n\n");
		}

		close(fh->mapfd);

		numbg = DIV_ROUND_UP(fh->numblocks, BG_SIZE);
		for (i = 0; i < numbg; i++)
			pthread_rwlock_destroy(&fh->bg[i].lock);
	}
	close(fh->imgfd);
	free(fh);

	return 0;
}

static int efes_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int ret;
	DIR *dirp;

	if (strcmp(path, "/") != 0) {
		fprintf(stderr, "readdir called with [%s]\n", path);
		return 0;
	}

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	pthread_mutex_lock(&readdir_lock);

	fd = dup(backing_dir_fd);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	dirp = fdopendir(fd);
	if (dirp == NULL) {
		ret = -errno;
		close(fd);
		goto out;
	}

	rewinddir(dirp);

	while (1) {
		struct dirent *dent;
		int len;
		unsigned char d_type;

		errno = 0;

		dent = readdir(dirp);
		if (dent == NULL) {
			ret = -errno;
			break;
		}

		len = strlen(dent->d_name);
		if (len < 5)
			continue;

		if (strcmp(dent->d_name + len - 4, ".img"))
			continue;

		d_type = dent->d_type;
		if (d_type == DT_UNKNOWN) {
			struct stat sbuf;

			ret = fstatat(backing_dir_fd, dent->d_name,
				      &sbuf, AT_SYMLINK_NOFOLLOW);
			if (ret == 0 && (sbuf.st_mode & S_IFMT) == S_IFREG)
				d_type = DT_REG;
		}

		if (d_type != DT_REG)
			continue;

		filler(buf, dent->d_name, NULL, 0);
	}

	closedir(dirp);

out:
	pthread_mutex_unlock(&readdir_lock);

	return ret;
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
static int efes_fallocate(const char *path, int mode, off_t offset,
			  off_t len, struct fuse_file_info *fi)
{
	if (!(mode & FALLOC_FL_PUNCH_HOLE))
		return -EINVAL;

	if (offset & 511)
		return -EINVAL;
	if (len & 511)
		return -EINVAL;
	if (len < 512)
		return -EINVAL;

	return 0;
}
#endif

static struct fuse_operations efes_oper = {
	.getattr	= efes_getattr,
	.open		= efes_open,
	.read		= efes_read,
	.write		= efes_write,
	.statfs		= efes_statfs,
	.release	= efes_release,
	.readdir	= efes_readdir,
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
	.fallocate	= efes_fallocate,
#endif
};

static void usage(const char *progname)
{
	fprintf(stderr,
"Usage: %s backingdir mountpoint [options]\n"
"\n"
"General options:\n"
"         --help            print help\n"
"    -V   --version         print version\n"
"    -b   --block-size=x    hash block size\n"
"    -h   --hash-algo=x     hash algorithm\n"
"\n", progname);
}

enum {
	KEY_HELP,
	KEY_VERSION,
};

struct efes_param
{
	char	*backing_dir;
	int	block_size;
	char	*hash_algo;
};

#define EFES_OPT(t, o)	{ t, offsetof(struct efes_param, o), -1, }

static struct fuse_opt efes_opts[] = {
	EFES_OPT("-b %u",		block_size),
	EFES_OPT("--block-size=%u",	block_size),
	EFES_OPT("-h %s",		hash_algo),
	EFES_OPT("--hash-algo=%s",	hash_algo),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("-V",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_END,
};

static int efes_opt_proc(void *data, const char *arg, int key,
			 struct fuse_args *outargs)
{
	struct efes_param *param = data;

	if (key == FUSE_OPT_KEY_NONOPT) {
		if (param->backing_dir == NULL) {
			param->backing_dir = strdup(arg);
			return 0;
		}
		return 1;
	}

	if (key == KEY_HELP) {
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		fuse_main(outargs->argc, outargs->argv, &efes_oper, NULL);
		exit(1);
	}

	if (key == KEY_VERSION) {
		fprintf(stderr, "efes version: %s\n", PACKAGE_VERSION);
		fuse_opt_add_arg(outargs, "--version");
		fuse_main(outargs->argc, outargs->argv, &efes_oper, NULL);
		exit(0);
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct efes_param param;
	int ret;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch\n");
		return 1;
	}

	memset(&param, 0, sizeof(param));

	if (fuse_opt_parse(&args, &param, efes_opts, efes_opt_proc) == -1)
		exit(1);

	if (param.backing_dir == NULL) {
		fprintf(stderr, "missing backing dir\n");
		fprintf(stderr, "see '%s --help' for usage\n", argv[0]);
		exit(1);
	}

	if (param.block_size)
		block_size = param.block_size;

	if (block_size <= 0 || (block_size & 7) != 0) {
		fprintf(stderr, "block size must be a multiple of 8\n");
		return 1;
	}

	if (param.hash_algo != NULL) {
		hash_algo = gcry_md_map_name(param.hash_algo);
		if (hash_algo == 0) {
			fprintf(stderr, "unknown hash algorithm "
					"name: %s\n", param.hash_algo);
			return 1;
		}
	}
	hash_size = gcry_md_get_algo_dlen(hash_algo);

	backing_dir_fd = open(param.backing_dir, O_RDONLY | O_DIRECTORY);
	if (backing_dir_fd < 0) {
		perror("open");
		return 1;
	}

	pthread_mutex_init(&readdir_lock, NULL);

	ret = fuse_main(args.argc, args.argv, &efes_oper, NULL);

	fuse_opt_free_args(&args);
	free(param.backing_dir);
	if (param.hash_algo != NULL)
		free(param.hash_algo);

	return ret;
}
