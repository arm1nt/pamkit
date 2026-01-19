#include "hooking.h"
#include "../util/log.h"
#include "../util/constants.h"

int
register_system_call_hook(const hook_data_t *syscall_hook)
{
    // Todo
    prinfo("register_system_call_hook");
    return PAMKIT_ERROR;
}

int
register_system_call_hooks(const hook_data_t syscall_hooks[])
{
    // Todo
    prinfo("register_system_call_hooks");
    return PAMKIT_ERROR;
}

void
deregister_system_call_hook(const hook_data_t *syscall_hook)
{
    // Todo
    prinfo("deregister_system_call_hook");
}

void
deregister_system_call_hooks(const hook_data_t syscall_hooks[])
{
    // Todo
    prinfo("deregister_system_call_hooks");
}

int
register_kernel_function_hook(const hook_data_t *kernel_function_hook)
{
    // Todo
    prinfo("register_kernel_function_hook");
    return PAMKIT_ERROR;
}

int
register_kernel_function_hooks(const hook_data_t kernel_function_hooks[])
{
    // Todo
    prinfo("register_kernel_function_hooks");
    return PAMKIT_ERROR;
}

void
deregister_kernel_function_hook(const hook_data_t *kernel_function_hook)
{
    // Todo
    prinfo("deregister_kernel_function_hook");
}

void
deregister_kernel_function_hooks(const hook_data_t kernel_function_hooks[])
{
    // Todo
    prinfo("deregister_kernel_function_hooks");
}
