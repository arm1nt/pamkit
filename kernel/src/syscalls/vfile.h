#ifndef _PAMKIT_SYSCALLS_VFILE_H
#define _PAMKIT_SYSCALLS_VFILE_H

#include <linux/types.h>
#include <linux/hashtable.h>

typedef unsigned long virtual_fd_t;

struct virtual_file_data {
    const char *data;
    const size_t data_len;
};
typedef struct virtual_file_data vfile_data_t;

// TODO: add a synchronization primitive
struct virtual_file {
    const pid_t pid;
    const virtual_fd_t vfd;

    const vfile_data_t *vfile_data;
    size_t pos;

    struct hlist_node node;
};
typedef struct virtual_file vfile_t;

/* Maps (pid+fd) to the corresponding virtual file state */
DEFINE_HASHTABLE(pid_fd_to_vfile, 16);

static virtual_fd_t
create_vfile(const pid_t pid, const virtual_fd_t vfd)
{
    // TODO
    return 0;
}

static vfile_t *
get_vfile(const pid_t pid, const virtual_fd_t vfd)
{
    // TODO
    return NULL;
}

static int
delete_vfile(const pid_t pid, const virtual_fd_t vfd)
{
    // TODO
    return -1;
}

#endif /* _PAMKIT_SYSCALLS_VFILE_H */
