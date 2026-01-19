#include "hooking.h"

extern int install_syscall_hooks(hook_data_t syscall_hooks[]);
extern int uninstall_syscall_hooks(hook_data_t syscall_hooks[]);

int
register_system_call_hooks(hook_data_t syscall_hooks[])
{
    return install_syscall_hooks(syscall_hooks);
}

int
deregister_system_call_hooks(hook_data_t syscall_hooks[])
{
    return uninstall_syscall_hooks(syscall_hooks);
}
