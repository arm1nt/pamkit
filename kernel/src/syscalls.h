#ifndef _PAMKIT_SYSCALLS_H
#define _PAMKIT_SYSCALLS_H

#include <linux/version.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "util/log.h"
#include "util/constants.h"
#include "hooking/hooking.h"

#if defined(CONFIG_X86_64) && (KERNEL_VERSION(4,17,0) <= LINUX_VERSION_CODE)
#define PAMKIT_PTREGS_STUBS 1
#endif

#define SYSCALL_HOOK_NAME(name) PREPEND_PAMKIT_TOKEN(name##_hook)
#define SYSCALL_ORIGINAL_NAME(name) PREPEND_PAMKIT_TOKEN(orig_##name)

#ifdef PAMKIT_PTREGS_STUBS

#define SYSCALL_HOOK_DEFINE(x, name, ...)   \
    asmlinkage long SYSCALL_HOOK_NAME(name)(const struct pt_regs *pt_regs)

#define SYSCALL_ORIGINAL_DEFINE(x, name, ...)   \
    static asmlinkage long (*SYSCALL_ORIGINAL_NAME(name))(const struct pt_regs *pt_regs)

/* Convenience macros to call the original syscall implementation inside the hook function */
#define READ_SYSCALL_ORIG X_SYSCALL_ORIG(read)
#define OPEN_SYSCALL_ORIG X_SYSCALL_ORIG(open)
#define OPENAT_SYSCALL_ORIG X_SYSCALL_ORIG(openat)
#define CLOSE_SYSCALL_ORIG X_SYSCALL_ORIG(close)
#define NEWFSTATAT_SYSCALL_ORIG X_SYSCALL_ORIG(newfstatat)
#define MMAP_SYSCALL_ORIG X_SYSCALL_ORIG(mmap)

#define X_SYSCALL_ORIG(name) SYSCALL_ORIGINAL_NAME(name)(pt_regs)

#else

#define SYSCALL_HOOK_DEFINE(x, name, ...)   \
    asmlinkage long SYSCALL_HOOK_NAME(name)(__MAP(x, __SC_DECL, __VA_ARGS__))

#define SYSCALL_ORIGINAL_DEFINE(x, name, ...)   \
    static asmlinkage long (*SYSCALL_ORIGINAL_NAME(name))(__MAP(x, __SC_DECL, __VA_ARGS__))

/* Convenience macros to call the original syscall implementation inside the hook function */
#define READ_SYSCALL_ORIG X_SYSCALL_ORIG(3, read,, fd,, buf,, count)
#define OPEN_SYSCALL_ORIG X_SYSCALL_ORIG(3, open,, filename,, flags,, mode)
#define OPENAT_SYSCALL_ORIG X_SYSCALL_ORIG(4, openat,, dfd,, filename,, flags,, mode)
#define CLOSE_SYSCALL_ORIG X_SYSCALL_ORIG(1, close,, fd)
#define NEWFSTATAT_SYSCALL_ORIG X_SYSCALL_ORIG(4, newfstatat,, dfd,, filename,, statbuf,, flag)
#define MMAP_SYSCALL_ORIG X_SYSCALL_ORIG(6, mmap,, addr,, len,, prot,, flags,, fd,, off)

#define X_SYSCALL_ORIG(x, name, ...) SYSCALL_ORIGINAL_NAME(name)(__MAP(x, __SC_ARGS, __VA_ARGS__))

#endif /* PAMKIT_PTREGS_STUBS */

#endif /* _PAMKIT_SYSCALLS_H */
