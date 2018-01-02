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

#define PACKAGE_VERSION "0.1"

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
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
#include "common.h"

#define DIV_ROUND_UP(x, y)	(((x) + (y) - 1) / (y))

struct efes_file_info
{
	int		imgfd;
	int		writable;
	uint64_t	file_size;
	uint64_t	numblocks;
	int		mapfd;
	int		dirty;
	uint8_t		dirty_block[0];
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int block_size = 1048576;
static int defrag_dirty_blocks;
static int hash_algo = GCRY_MD_SHA512;
static int hash_size;
static int trim_cipher_algo = GCRY_CIPHER_AES128;
static int trim_key_size;

static int backing_dir_fd;
static pthread_mutex_t readdir_lock;
static pthread_mutex_t gcrypt_lock;
static int trim_fill;
static uint8_t trim_key[64];

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

static int efes_open(const char *path, struct fuse_file_info *fi)
{
	int len;
	int writable;
	int flags;
	int imgfd;
	struct stat buf;
	int ret;
	int mapfd;
	uint64_t numblocks;
	struct efes_file_info *fh;

	if (path[0] != '/') {
		fprintf(stderr, "open called with [%s]\n", path);
		return -ENOENT;
	}

	len = strlen(path);
	if (len < 6 || strcmp(path + len - 4, ".img"))
		return -ENOENT;

	writable = !((fi->flags & O_ACCMODE) == O_RDONLY);

	flags = fi->flags;
	if ((flags & O_ACCMODE) == O_WRONLY)
		flags = (flags & ~O_ACCMODE) | O_RDWR;

	imgfd = openat(backing_dir_fd, path + 1, flags);
	if (imgfd < 0)
		return -errno;

	mapfd = -1;
	if (writable) {
		char mappath[len + 1];

		strcpy(mappath, path);
		strcpy(mappath + len - 4, ".map");

		mapfd = openat(backing_dir_fd, mappath + 1, O_WRONLY);
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

	fh = malloc(sizeof(*fh) + (writable ? numblocks : 0));
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
	fh->dirty = 0;
	if (writable)
		memset(fh->dirty_block, 0, numblocks);

	fi->fh = (uint64_t)fh;

	return 0;
}

static int efes_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;

	return pread(fh->imgfd, buf, size, offset);
}

static int efes_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;
	off_t written;

	if (!fh->writable)
		return -EBADF;

	if (size > INT_MAX)
		size = INT_MAX;

	written = 0;
	while (written < size) {
		size_t towrite;
		off_t block;
		int ret;

		if (offset >= fh->file_size)
			break;

		towrite = size - written;
		if (offset + towrite > fh->file_size)
			towrite = fh->file_size - offset;
		if (towrite > block_size - (offset % block_size))
			towrite = block_size - (offset % block_size);

		block = offset / block_size;

		ret = pwrite(fh->imgfd, buf, towrite, offset);
		if (ret < 0)
			return written ? written : -errno;

		if (ret == block_size) {
			uint8_t hash[hash_size];

			gcry_md_hash_buffer(hash_algo, hash, buf, block_size);
			xpwrite(fh->mapfd, hash, hash_size, block * hash_size);

			fh->dirty_block[block] = 0;
		} else {
			if (!fh->dirty)
				fh->dirty = 1;
			fh->dirty_block[block] = 1;
		}

		buf += ret;
		offset += ret;

		written += ret;
	}

	return written;
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

	xsem_wait(&me->sem0);

	while (1) {
		off_t block;
		uint8_t buf[block_size];
		int ret;
		uint8_t hash[hash_size];

		for (block = cs->block; block < fh->numblocks; block++) {
			if (fh->dirty_block[block])
				break;
		}

		if (block == fh->numblocks) {
			cs->block = fh->numblocks;
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

		ret = xpread(fh->imgfd, buf, block_size, block * block_size);
		if (ret < block_size && block != fh->numblocks - 1) {
			fprintf(stderr, "commit_thread: short read on "
					"block %Ld\n", (long long)block);
			break;
		}

		xsem_post(&me->next->sem0);

		if (defrag_dirty_blocks)
			xpwrite(fh->imgfd, buf, ret, block * block_size);

		gcry_md_hash_buffer(hash_algo, hash, buf, ret);

		xsem_wait(&me->sem0);

		xpwrite(fh->mapfd, hash, hash_size, block * hash_size);
	}

	xsem_post(&me->next->sem0);

	return NULL;
}

static void update_mapfile(struct efes_file_info *fh, const char *path)
{
	uint64_t num_dirty;
	uint64_t i;
	struct commit_state cs;

	num_dirty = 0;
	for (i = 0; i < fh->numblocks; i++) {
		if (fh->dirty_block[i])
			num_dirty++;
	}

	if (num_dirty) {
		if (stderr_is_tty()) {
			fprintf(stderr, "committing %s (%Ld dirty blocks)\n",
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
}

static int efes_release(const char *path, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;

	if (fh->writable) {
		if (fh->dirty)
			update_mapfile(fh, path);
		close(fh->mapfd);
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
			int ret;

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
static ssize_t xwrite(const char *path, const void *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	size_t written;

	written = 0;
	while (written < size) {
		int ret;

		ret = efes_write(path, buf, size - written, offset, fi);
		if (ret < 0)
			return written ? written : -errno;

		if (ret == 0)
			break;

		buf += ret;
		offset += ret;

		written += ret;
	}

	return written;
}

static int efes_fallocate(const char *path, int mode, off_t offset,
			  off_t len, struct fuse_file_info *fi)
{
	struct efes_file_info *fh = (void *)fi->fh;
	gcry_cipher_hd_t hd;

	if (!(mode & FALLOC_FL_PUNCH_HOLE))
		return -EINVAL;

	if (offset & 511)
		return -EINVAL;
	if (len & 511)
		return -EINVAL;
	if (len < 512)
		return -EINVAL;

	if (!trim_fill)
		return 0;

	/*
	 * libgcrypt 1.6.3 segfaults if gcry_cipher_open() calls
	 * are not strictly serialised.
	 */
	pthread_mutex_lock(&gcrypt_lock);

	if (gcry_cipher_open(&hd, trim_cipher_algo, GCRY_CIPHER_MODE_ECB, 0)) {
		fprintf(stderr, "efes_fallocate: error opening cipher\n");
		pthread_mutex_unlock(&gcrypt_lock);
		return -EIO;
	}

	if (gcry_cipher_setkey(hd, trim_key, trim_key_size)) {
		fprintf(stderr, "efes_fallocate: error setting key\n");
		gcry_cipher_close(hd);
		pthread_mutex_unlock(&gcrypt_lock);
		return -EIO;
	}

	pthread_mutex_unlock(&gcrypt_lock);

	while (len) {
		uint8_t buf[block_size];
		size_t totrim;
		uint32_t *ptr;
		uint64_t ctr;
		int i;

		if (offset >= fh->file_size)
			break;

		totrim = len;
		if (offset + totrim > fh->file_size)
			totrim = fh->file_size - offset;
		if (totrim > sizeof(buf) - (offset % sizeof(buf)))
			totrim = sizeof(buf) - (offset % sizeof(buf));

		ptr = (uint32_t *)buf;
		ctr = offset / 8;

		for (i = 0; i < totrim; i += 8) {
			*ptr++ = htonl(ctr >> 32);
			*ptr++ = htonl(ctr & 0xffffffff);
			ctr++;
		}

		if (gcry_cipher_encrypt(hd, buf, totrim, buf, totrim)) {
			fprintf(stderr, "efes_fallocate: error "
					"encrypting block\n");
			gcry_cipher_close(hd);
			return -EIO;
		}

		if (xwrite(path, buf, totrim, offset, fi) != totrim) {
			gcry_cipher_close(hd);
			return -EIO;
		}

		offset += totrim;
		len -= totrim;
	}

	gcry_cipher_close(hd);

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
"         --defrag          defragment written blocks on image close\n"
"    -h   --hash-algo=x     hash algorithm\n"
"         --trim-cipher=x   trim fill cipher\n"
"         --trim-key-file=x trim fill key file\n"
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
	int	defrag_dirty_blocks;
	char	*hash_algo;
	char	*trim_cipher;
	char	*trim_key_file;
};

#define EFES_OPT(t, o)	{ t, offsetof(struct efes_param, o), -1, }

static struct fuse_opt efes_opts[] = {
	EFES_OPT("-b %u",		block_size),
	EFES_OPT("--block-size=%u",	block_size),
	EFES_OPT("--defrag",		defrag_dirty_blocks),
	EFES_OPT("-h %s",		hash_algo),
	EFES_OPT("--hash-algo=%s",	hash_algo),
	EFES_OPT("--trim-cipher=%s",	trim_cipher),
	EFES_OPT("--trim-key-file=%s",	trim_key_file),
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

	if (param.block_size) {
		if ((param.block_size & 7) != 0) {
			fprintf(stderr, "error: block size must be "
					"a multiple of 8\n");
			return 1;
		}
		block_size = param.block_size;
	}

	if (param.defrag_dirty_blocks)
		defrag_dirty_blocks = 1;

	if (param.hash_algo != NULL) {
		hash_algo = gcry_md_map_name(param.hash_algo);
		if (hash_algo == 0) {
			fprintf(stderr, "unknown hash algorithm "
					"name: %s\n", param.hash_algo);
			return 1;
		}
	}
	hash_size = gcry_md_get_algo_dlen(hash_algo);

	if (param.trim_cipher != NULL) {
		trim_cipher_algo = gcry_cipher_map_name(param.trim_cipher);
		if (trim_cipher_algo == 0) {
			fprintf(stderr, "unknown cipher algorithm "
					"name: %s\n", param.trim_cipher);
			return 1;
		}
	}
	trim_key_size = gcry_cipher_get_algo_keylen(trim_cipher_algo);

	backing_dir_fd = open(param.backing_dir, O_RDONLY | O_DIRECTORY);
	if (backing_dir_fd < 0) {
		perror("open");
		return 1;
	}

	pthread_mutex_init(&readdir_lock, NULL);

	pthread_mutex_init(&gcrypt_lock, NULL);

	if (param.trim_key_file != NULL) {
		int fd;
		int ret;

		trim_fill = 1;

		fd = open(param.trim_key_file, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "cannot open trim key file %s: %s\n",
				param.trim_key_file, strerror(errno));
			return 1;
		}

		ret = read(fd, trim_key, trim_key_size);
		if (ret != trim_key_size) {
			fprintf(stderr, "cannot read trim key file: "
					"read %d bytes, wanted %d\n",
				ret, trim_key_size);
			return 1;
		}

		close(fd);
	}

	ret = fuse_main(args.argc, args.argv, &efes_oper, NULL);

	memset(trim_key, 0, sizeof(trim_key));

	fuse_opt_free_args(&args);
	free(param.backing_dir);
	if (param.hash_algo != NULL)
		free(param.hash_algo);
	if (param.trim_cipher != NULL)
		free(param.trim_cipher);
	if (param.trim_key_file != NULL)
		free(param.trim_key_file);

	return ret;
}
