#ifndef _PAMKIT_SYSCALLS_H
#define _PAMKIT_SYSCALLS_H

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mman.h>

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

#define GEN_SYSCALL_HOOK_DATA(name)     \
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name(#name), &SYSCALL_ORIG_NAME(name), SYSCALL_HOOK_NAME(name), __NR_##name)

#ifdef PAMKIT_PTREGS_STUBS

#define SYSCALL_HOOK(name, ...)         \
    SYSCALL_ORIGINAL_DEFINE(name);      \
    SYSCALL_HOOK_DEFINE(name)

#define SYSCALL_ORIGINAL_DEFINE(name)   \
    static asmlinkage long (*SYSCALL_ORIG_NAME(name))(const struct pt_regs *pt_regs)

#define SYSCALL_HOOK_DEFINE(name)                                               \
    asmlinkage long SYSCALL_HOOK_NAME(name)(const struct pt_regs *pt_regs);     \
    asmlinkage long SYSCALL_HOOK_NAME(name)(const struct pt_regs *pt_regs)

#define SYSCALL_ORIG_ARGS(x,...) x

#define FIRST_ARG(x, _type) (_type) x->di
#define SECOND_ARG(x, _type) (_type) x->si
#define THIRD_ARG(x, _type) (_type) x->dx
#define FOURTH_ARG(x, _type) (_type) x->r10
#define FIFTH_ARG(x, _type) (_type) x->r8
#define SIXTH_ARG(x, _type) (_type) x->r9

#else /* !PAMKIT_PTREGS_STUBS */

#define SYSCALL_HOOK(name, ...)                     \
    SYSCALL_ORIGINAL_DEFINE(name, __VA_ARGS__);     \
    SYSCALL_HOOK_DEFINE(name, __VA_ARGS__)

#define SYSCALL_ORIGINAL_DEFINE(name, ...)          \
    static asmlinkage long (*SYSCALL_ORIG_NAME(name))(__VA_ARGS__)

#define SYSCALL_HOOK_DEFINE(name, ...)                      \
    asmlinkage long SYSCALL_HOOK_NAME(name)(__VA_ARGS__);   \
    asmlinkage long SYSCALL_HOOK_NAME(name)(__VA_ARGS__)

#define SYSCALL_ORIG_ARGS(x, ...) __VA_ARGS__

#endif /* PAMKIT_PTREGS_STUBS */

/* Convenience macros to call the original syscall implementation from inside a hook function */
/* Not necessary and overkill, yes, but wanted to try doing it like this. */
#include "generated/syscall_orig_x64.h"

#endif /* _PAMKIT_SYSCALLS_H */
