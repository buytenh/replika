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

#ifndef __COMMON_H
#define __COMMON_H

#include <semaphore.h>

struct worker_thread {
	sem_t sem0;
	sem_t sem1;
	struct worker_thread *next;
};

ssize_t xpread(int fd, void *buf, size_t count, off_t offset);
ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset);
void xsem_post(sem_t *sem);
void xsem_wait(sem_t *sem);

void run_threads(void *(*handler)(void *));
int should_report_progress(void);
void progress_reported(void);


#endif
