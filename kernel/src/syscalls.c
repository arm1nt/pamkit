#include "syscalls.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

// TODO: move (and refactor) the logic from 'sys.c' into this file

SYSCALL_ORIGINAL_DEFINE(3, read, unsigned int, fd, char __user *, buf, size_t, count);
SYSCALL_HOOK_DEFINE(3, read, unsigned int, fd, char __user *, buf, size_t, count)
{
    long ret = SYSCALL_ORIG_READ;
    return ret;
}

SYSCALL_ORIGINAL_DEFINE(3, open, const char __user *, filename, int, flags, umode_t, mode);
SYSCALL_HOOK_DEFINE(3, open, const char __user *, filename, int, flags, umode_t, mode)
{
    long ret = SYSCALL_ORIG_OPEN;
    return ret;
}

SYSCALL_ORIGINAL_DEFINE(4, openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode);
SYSCALL_HOOK_DEFINE(4, openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
{
    long ret = SYSCALL_ORIG_OPENAT;
    return ret;
}

SYSCALL_ORIGINAL_DEFINE(4, newfstatat, int, dfd, const char __user *, filename, struct stat __user *, statbuf, int, flag);
SYSCALL_HOOK_DEFINE(4, newfstatat, int, dfd, const char __user *, filename, struct stat __user *, statbuf, int, flag)
{
    long ret = SYSCALL_ORIG_NEWFSTATAT;
    return ret;
}

SYSCALL_ORIGINAL_DEFINE(1, close, int, fd);
SYSCALL_HOOK_DEFINE(1, close, int, fd)
{
    long ret = SYSCALL_ORIG_CLOSE;
    return ret;
}

SYSCALL_ORIGINAL_DEFINE(6, mmap, unsigned long, addr, unsigned long, len, int, prot, int, flags, int, fd, long off);
SYSCALL_HOOK_DEFINE(6, mmap, unsigned long, addr, unsigned long, len, int, prot, int, flags, int, fd, long, off)
{
    long ret = SYSCALL_ORIG_MMAP;
    return ret;
}

hook_data_t pamkit_syscall_hooks[] = {
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("read"), &SYSCALL_ORIG_NAME(read), SYSCALL_HOOK_NAME(read), __NR_read),
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("open"), &SYSCALL_ORIG_NAME(open), SYSCALL_HOOK_NAME(open), __NR_open),
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("openat"), &SYSCALL_ORIG_NAME(openat), SYSCALL_HOOK_NAME(openat), __NR_openat),
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("newfstatat"), &SYSCALL_ORIG_NAME(newfstatat), SYSCALL_HOOK_NAME(newfstatat), __NR_newfstatat),
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("close"), &SYSCALL_ORIG_NAME(close), SYSCALL_HOOK_NAME(close), __NR_close),
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("mmap"), &SYSCALL_ORIG_NAME(mmap), SYSCALL_HOOK_NAME(mmap), __NR_mmap),
    SYSCALL_HOOK_DATA_EMPTY
};
