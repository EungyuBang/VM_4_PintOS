#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#include "filesys/off_t.h"
#include "stddef.h"
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void munmap(void *addr);
extern struct lock filesys_lock;

#endif /* userprog/syscall.h */
