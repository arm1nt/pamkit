//header file
#ifndef _READ_TABLE_H
#define _READ_TABLE_H

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

//Linked list that stores the read states for the processes that have opened the virtual file.
struct virtual_read_table {
    pid_t pid;
    long offset;
    struct virtual_read_table *next;
};
typedef struct virtual_read_table vrt_t;

#define PAMKIT_SUCCESS 0
#define VRT_SIZE (sizeof(vrt_t))

int create_new_read_entry(pid_t pid);

vrt_t * get_table_entry_by_pid(pid_t pid);

int remove_table_entry_by_pid(pid_t pid);

void reset_table_entry_by_pid(pid_t pid);

void destroy_list(void);

void print_list(void);

#endif /* _READ_TABLE_H */