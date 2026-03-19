#ifndef PAMKIT_SYSCALLS_VFILE_H
#define PAMKIT_SYSCALLS_VFILE_H

#include "../util/log.h"

#include <linux/hashtable.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

typedef unsigned long virtual_fd_t;

static atomic_t global_vfd_counter = ATOMIC_INIT(999);

static inline virtual_fd_t
get_new_virtual_fd(const pid_t pid)
{
    return (virtual_fd_t) atomic_inc_return(&global_vfd_counter);
}

struct virtual_file_data {
    const char *data;
    const size_t data_len;
};
typedef struct virtual_file_data vfile_data_t;

struct virtual_file {
    pid_t pid;
    virtual_fd_t vfd;

    const vfile_data_t *vfile_data;
    size_t pos;

    struct mutex vf_mutex;
    struct kref refcount;
    struct hlist_node node;
};
typedef struct virtual_file vfile_t;

/* Maps (pid+fd) to the corresponding virtual file state */
static DEFINE_SPINLOCK(vfile_hashtable_lock);
static DEFINE_HASHTABLE(pid_fd_to_vfile, 16);

static void
vfile_release(struct kref *ref)
{
    vfile_t *vfile = container_of(ref, vfile_t, refcount);
    mutex_destroy(&vfile->vf_mutex);
    kfree(vfile);
}

static inline void
put_vfile(vfile_t *vfile)
{
    if (vfile) {
        kref_put(&vfile->refcount, vfile_release);
    }
}

static virtual_fd_t
create_vfile(const pid_t pid, const vfile_data_t *vfile_data)
{
    const virtual_fd_t vfd = get_new_virtual_fd(pid);

    vfile_t *vfile = kzalloc(sizeof(vfile_t), GFP_KERNEL);
    if (unlikely(!vfile)) {
        prerr_ratelimited("Failed to allocate memory for virtual file");
        return 0;
    }

    vfile->pid = pid;
    vfile->vfd = vfd;
    vfile->vfile_data = vfile_data;
    vfile->pos = 0;
    mutex_init(&vfile->vf_mutex);
    kref_init(&vfile->refcount);

    spin_lock(&vfile_hashtable_lock);
    hash_add(pid_fd_to_vfile, &vfile->node, vfd);
    spin_unlock(&vfile_hashtable_lock);

    return vfd;
}

/* Note: Caller must explicitly unpin the vfiles refcount */
static vfile_t *
get_vfile(const pid_t pid, const virtual_fd_t vfd)
{
    vfile_t *current_vfile;

    spin_lock(&vfile_hashtable_lock);

    hash_for_each_possible(pid_fd_to_vfile, current_vfile, node, vfd) {
        if (current_vfile->pid == pid && current_vfile->vfd == vfd) {
            kref_get(&current_vfile->refcount);
            spin_unlock(&vfile_hashtable_lock);
            return current_vfile;
        }
    }

    spin_unlock(&vfile_hashtable_lock);
    return NULL;
}

static void
delete_vfile(const pid_t pid, const virtual_fd_t vfd)
{
    spin_lock(&vfile_hashtable_lock);

    vfile_t *current_vfile;
    hash_for_each_possible(pid_fd_to_vfile, current_vfile, node, vfd) {
        if (current_vfile->pid == pid && current_vfile->vfd == vfd) {
            hash_del_rcu(&current_vfile->node);
            spin_unlock(&vfile_hashtable_lock);

            put_vfile(current_vfile);
            return;
        }
    }

    spin_unlock(&vfile_hashtable_lock);
}

#endif /* PAMKIT_SYSCALLS_VFILE_H */
