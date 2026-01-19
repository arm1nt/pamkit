#ifndef _PAMKIT_HOOKING_H
#define _PAMKIT_HOOKING_H

#include <linux/version.h>

#if defined(PAMKIT_FTRACE_HOOKING) && defined(CONFIG_FTRACE) && defined(CONFIG_DYNAMIC_FTRACE)
#include <linux/ftrace.h>
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define _arch_syscall_name(name) "__x86_64" name
#else
#define _arch_syscall_name(name) name
#endif

#define HOOK_DATA_EMPTY { .name = NULL, .orig_function = NULL, .hook_function = NULL }

#define HOOK_DATA_DEFINE_SYSCALL(_name, _orig_function, _hook_function)     \
    {                                                                       \
        .name = (_name),                                                    \
        .orig_function = (unsigned long *) (_orig_function),                \
        .hook_function = (unsigned long *) (_hook_function),                \
    }

#define HOOK_DATA_INIT_SYSCALL(_hook_name, _name, _orig_function, _hook_function)   \
    const hook_data_t _hook_name = HOOK_DATA_DEFINE_SYSCALL(_name, _orig_function, _hook_function)

#define HOOK_DATA_DEFINE_KERNEL_FUNCTION(_name, _orig_function, _hook_function)     \
    {                                                                               \
        .name = (_name),                                                            \
        .orig_function = (unsigned long *) (_orig_function),                        \
        .hook_function = (unsigned long *) (_hook_function),                        \
    }

#define HOOK_DATA_INIT_KERNEL_FUNCTION(_hook_name, _name, _orig_function, _hook_function) \
    const hook_data_t _hook_name = HOOK_DATA_DEFINE_KERNEL_FUNCTION(_name, _orig_function, _hook_function)

struct hook_data {
    char *name; // Name of the original function such that we can e.g. resolve its original address

    unsigned long *orig_function;
    unsigned long *hook_function;

    #if defined(PAMKIT_FTRACE_HOOKING) && defined(CONFIG_FTRACE) && defined(CONFIG_DYNAMIC_FTRACE)
    struct ftrace_ops fops;
    #endif
};
typedef struct hook_data hook_data_t;

int register_system_call_hook(const hook_data_t *syscall_hook);

int register_system_call_hooks(const hook_data_t syscall_hooks[]);

void deregister_system_call_hook(const hook_data_t *syscall_hook);

void deregister_system_call_hooks(const hook_data_t syscall_hooks[]);

int register_kernel_function_hook(const hook_data_t *kernel_function_hook);

int register_kernel_function_hooks(const hook_data_t kernel_function_hooks[]);

void deregister_kernel_function_hook(const hook_data_t *kernel_function_hook);

void deregister_kernel_function_hooks(const hook_data_t kernel_function_hooks[]);

#endif /* _PAMKIT_HOOKING_H */
