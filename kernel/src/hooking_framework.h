#ifndef _HOOKING_FRAMEWORK_H
#define _HOOKING_FRAMEWORK_H

#include <linux/ftrace.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
#include <linux/kallsyms.h>
#else
#include <linux/kprobes.h>
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
#endif


/**
 * @brief Stores information about the function to be hooked
 * 
 */
struct function_hook {
    char *name; //name of the function, so that we can resolve and store its original address.

    unsigned long *orig_function; //points to the original function implementation.
    unsigned long *hook_function; //points to the function that should be executed instead of the function to be hooked.

    struct ftrace_ops fops; //to register and unregister the hook.
};
typedef struct function_hook function_hook_t;


int do_hooking(function_hook_t *hook_array, int size);

int undo_hooking(function_hook_t *hook_array, int size);


#endif /* _HOOKING_FRAMEWORK_H */