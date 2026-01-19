#ifndef _PAMKIT_SYSCALLS_H
#define _PAMKIT_SYSCALLS_H

#include <linux/version.h>
#include <linux/string.h>
#include <linux/syscalls.h>

#include "util/log.h"
#include "util/constants.h"
#include "hooking/hooking.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PAMKIT_PTREGS_STUBS 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define __syscall_name(name) "__x64_sys_" name
#else
#define __syscall_name(name) "" name
#endif

#define SYSCALL_HOOK_NAME(name) pamkit_##name##_hook
#define SYSCALL_ORIG_NAME(name) pamkit_orig_##name

#ifdef PAMKIT_PTREGS_STUBS

#define SYSCALL_HOOK_DEFINE(x, name, ...)                                       \
    asmlinkage long SYSCALL_HOOK_NAME(name)(const struct pt_regs *pt_regs);     \
    asmlinkage long SYSCALL_HOOK_NAME(name)(const struct pt_regs *pt_regs)

#define SYSCALL_ORIGINAL_DEFINE(x, name, ...)   \
    static asmlinkage long (*SYSCALL_ORIG_NAME(name))(const struct pt_regs *pt_regs)

#define FIRST_ARG(x, _type) (_type) x->di
#define SECOND_ARG(x, _type) (_type) x->si
#define THIRD_ARG(x, _type) (_type) x->dx
#define FOURTH_ARG(x, _type) (_type) x->r10
#define FIFTH_ARG(x, _type) (_type) x->r8
#define SIXTH_ARG(x, _type) (_type) x->r9

/* Convenience macros to call the original syscall implementation from inside a hook function */
#define SYSCALL_ORIG_READ X_SYSCALL_ORIG(read)
#define SYSCALL_ORIG_OPEN X_SYSCALL_ORIG(open)
#define SYSCALL_ORIG_OPENAT X_SYSCALL_ORIG(openat)
#define SYSCALL_ORIG_NEWFSTATAT X_SYSCALL_ORIG(newfstatat)
#define SYSCALL_ORIG_CLOSE X_SYSCALL_ORIG(close)
#define SYSCALL_ORIG_MMAP X_SYSCALL_ORIG(mmap)

#define X_SYSCALL_ORIG(name) SYSCALL_ORIG_NAME(name)(pt_regs)

#else /* !PAMKIT_PTREGS_STUBS */

#define SYSCALL_HOOK_DEFINE(x, name, ...)                                   \
    asmlinkage long SYSCALL_HOOK_NAME(__MAP(x, __SC_DECL, __VA_ARGS__));    \
    asmlinkage long SYSCALL_HOOK_NAME(__MAP(x, __SC_DECL, __VA_ARGS__))

#define SYSCALL_ORIGINAL_DEFINE(x, name, ...)   \
    static asmlinkage long (*SYSCALL_ORIG_NAME(name))(__MAP(x, __SC_DECL, __VA_ARGS__))

/* Convenience macros to call the original syscall implementation from inside a hook function */
/* https://syscalls64.paolostivanin.com/ */
#define SYSCALL_ORIG_READ X_SYSCALL_ORIG(3, read,, fd,, buf,, count)
#define SYSCALL_ORIG_OPEN X_SYSCALL_ORIG(3, open,, filename,, flags,, mode)
#define SYSCALL_ORIG_OPENAT X_SYSCALL_ORIG(4, openat,, dfd,, filename,, flags,, mode)
#define SYSCALL_ORIG_NEWFSTATAT X_SYSCALL_ORIG(4, newfstatat,, dfd,, filename,, statbuf,, flag)
#define SYSCALL_ORIG_CLOSE X_SYSCALL_ORIG(1, close,, fd)
#define SYSCALL_ORIG_MMAP X_SYSCALL_ORIG(6, mmap,, addr,, len,, prot,, flags,, fd,, off)

#define X_SYSCALL_ORIG(x, name, ...) SYSCALL_ORIG_NAME(name)(__MAP(x, __SC_ARGS, __VA_ARGS__))

#endif /* PAMKIT_PTREGS_STUBS */

#endif /* _PAMKIT_SYSCALLS_H */
