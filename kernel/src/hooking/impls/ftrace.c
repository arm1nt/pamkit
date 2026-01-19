#include "helpers.h"

#if defined(PAMKIT_FTRACE_SYSCALL_HOOKING)

#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/ftrace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
#include <linux/ftrace_regs.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)

static void notrace
ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *fops, struct ftrace_regs *fregs)
{
    if (!within_module(parent_ip, THIS_MODULE)) {
        /* overwrite the instruction pointer that will be restored by the trampoline to point to our hook */

        #if LINUX_VERSION_CODE < KERNEL_VERSION(6,13,0)
        fregs->regs.ip = (unsigned long) fops->private;
        #else
        (arch_ftrace_regs(fregs))->regs.rip = (unsigned long) fops->private;
        #endif
    }
}

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) */

static void notrace
ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *fops, struct pt_regs *regs)
{
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long) fops->private;
    }
}

#endif

static int
register_function(hook_data_t *hook)
{
    int ret = 0;

    void *orig_function_addr = pamkit_lookup_symbol_addr(hook->name);
    if (!orig_function_addr) {
        prerr("Unable to get handle to original implementation of '%s'", hook->name);
        return PAMKIT_GENERIC_ERROR;
    }
    *(hook->orig_function_addr) = (uintptr_t) orig_function_addr;

    struct ftrace_ops *local_fops = &hook->fops;

    local_fops->func = ftrace_callback;

    local_fops->flags =
        FTRACE_OPS_FL_SAVE_REGS
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
        | FTRACE_OPS_FL_RECURSION
        #else
        | FTRACE_OPS_FL_RECURSION_SAFE
        #endif
        | FTRACE_OPS_FL_IPMODIFY;

    local_fops->private = hook->hook_function_addr;

    if ((ret = ftrace_set_filter_ip(local_fops, *(hook->orig_function_addr), 0, 0))) {
        prerr("'ftrace_set_filter_ip' failed while installing hook for '%s'", hook->name);
        return ret;
    }

    if ((ret = register_ftrace_function(local_fops))) {
        prerr("'register_ftrace_function' failed while installing hook for '%s'", hook->name);
        ftrace_set_filter_ip(&(hook->fops), *(hook->orig_function_addr), 1, 0);
        return ret;
    }

    hook->installed = true;

    return PAMKIT_GENERIC_SUCCESS;
}

static int
unregister_function(hook_data_t *hook)
{
    int ret = 0;

    if ((ret = unregister_ftrace_function(&(hook->fops)))) {
        prwarn("'unregister_ftrace_function' failed while removing hook for '%s'", hook->name);
    }

    if ((ret = ftrace_set_filter_ip(&(hook->fops), *(hook->orig_function_addr), 1, 0))) {
        prwarn("'ftrace_set_filter_ip' failed while removing hook for '%s'", hook->name);
    }

    return ret;
}

int
install_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to install syscall hooks...");

    hook_data_t *hook = &syscall_hooks[0];
    while(hook->hook_function_addr) {

        if (register_function(hook)) {
            prerr("Failed to hook '%s'. Rolling back changes...", hook->name);
            uninstall_syscall_hooks(syscall_hooks);
            return PAMKIT_GENERIC_ERROR;
        }

        hook++;
    }

    prdebug("Successfully installed the syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

int
uninstall_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to remove any installed syscall hooks...");

    hook_data_t *hook = &syscall_hooks[0];
    while (hook->hook_function_addr) {

        if (hook->installed) {
            prdebug("Uninstalling syscall hook for '%s'", hook->name);
            unregister_function(hook);
        }

        hook++;
    }

    prdebug("Successfully de-registered the installed syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

#endif /* PAMKIT_FTRACE_SYSCALL_HOOKING */