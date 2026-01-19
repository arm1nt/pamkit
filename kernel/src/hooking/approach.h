/**
 * Verifies and possibly decides on the syscall hooking approach to be used.
 *
 * - If an approach is specified, check if the system supports it
 * - If no approach is specified, select a suitable approach.
 */

#ifndef _PAMKIT_HOOKING_APPROACH_H
#define _PAMKIT_HOOKING_APPROACH_H

#include <linux/version.h>

#if defined(PAMKIT_FTRACE_SYSCALL_HOOKING)

#if (!defined(CONFIG_FTRACE)) || (!defined(CONFIG_DYNAMIC_FTRACE))
#error "Cannot use ftrace for hooking syscalls because the kernel is not configured to support ftrace"
#endif

#elif defined(PAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,5)
#error "Since kernel version 6.8.5 the syscall table is no longer used for system call dispatching"
#endif

#elif defined(PAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING)

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,5)
#error "The 'x64_sys_call' function does not exist in kernels prior to version 6.8.5"
#endif

#else /* No user specified hooking implementation preference */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,5)

#define PAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,5)

#define PAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING

#else
#error "No suitable hooking implementation found!"
#endif

#endif

#endif /* _PAMKIT_HOOKING_APPROACH_H */
