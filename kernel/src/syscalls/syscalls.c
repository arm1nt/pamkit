#include "hook_defs.h"
#include "pam_config.h"
#include "vfile.h"
#include "../util/log.h"

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/spinlock.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/compiler.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/io.h>

#pragma GCC optimize("-fno-optimize-sibling-calls")

static long
replace_pam_rules_in_buffer(char __user *buffer, const size_t read_bytes, const disk_mod_config_t *disk_mod_config)
{
    // TODO
    return -1;
}

static long
do_virtual_file_read(char __user *buffer, const size_t req_bytes, const vfile_t *virtual_file)
{
    // TODO:
    return -1;
}

SYSCALL_HOOK(read, unsigned int fd, char __user *buf, size_t count)
{
    long ret = SYSCALL_ORIG_READ(pt_regs, fd, buf, count);
    return ret;
}

SYSCALL_HOOK(open, const char __user *filename, int flags, umode_t mode)
{
    long ret = SYSCALL_ORIG_OPEN(pt_regs, filename, flags, mode);
    return ret;
}

SYSCALL_HOOK(openat, int dfd, const char __user *filename, int flags, umode_t mode)
{
    long ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    return ret;
}

SYSCALL_HOOK(newfstatat, int dfd, const char __user *filename, struct stat __user *statbuf, int flag)
{
    long ret = SYSCALL_ORIG_NEWFSTATAT(pt_regs, dfd, filename, statbuf, flag);
    return ret;
}

SYSCALL_HOOK(close, int fd)
{
    long ret = SYSCALL_ORIG_CLOSE(pt_regs, fd);
    return ret;
}

SYSCALL_HOOK(mmap, unsigned long addr, unsigned long len, int prot, int flags, int fd, long off)
{
    long ret = SYSCALL_ORIG_MMAP(pt_regs, addr, len, prot, flags, fd, off);
    return ret;
}

hook_data_t pamkit_syscall_hooks[] = {
    GEN_SYSCALL_HOOK_DATA(read),
    GEN_SYSCALL_HOOK_DATA(open),
    GEN_SYSCALL_HOOK_DATA(openat),
    GEN_SYSCALL_HOOK_DATA(newfstatat),
    GEN_SYSCALL_HOOK_DATA(close),
    GEN_SYSCALL_HOOK_DATA(mmap),
    SYSCALL_HOOK_DATA_EMPTY
};
