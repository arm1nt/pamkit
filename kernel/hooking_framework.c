#include "hooking_framework.h"


/**
 * @brief Obtains memory address of given symbol.
 * 
 * @param name name of symbol
 * @return unsigned memory address of symbol
 */
static unsigned long
_get_addr_by_name(const char *name)
{
    unsigned long retval;

    //starting from kernel version 4.17, all syscalls start with '__x64_',
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
    if (strncmp(name, "__x64_", 6) == 0) {
        name +=6;
    }
    #endif

    #if KERNEL_VERSION(5,7,0) <= LINUX_VERSION_CODE
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    register_kprobe(&kp);
    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    retval = kallsyms_lookup_name(name);
    #else
    retval = kallsyms_lookup_name(name);
    #endif

    return retval;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void notrace
ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *fops, struct ftrace_regs *fregs)
{
    if (!within_module(parent_ip, THIS_MODULE)) {
        //overwrite the instruction pointer that will be restored by the trampoline to our hook function address.
        fregs->regs.ip = (unsigned long) fops->private;
    }
}
#else
static void notrace
ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *fops, struct pt_regs *regs)
{
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long) fops->private;
    }
}
#endif


/**
 * @brief Get the address of the function to be hooked, and set the orig_function member of the
 *  function_hook_t struct to this address.
 * 
 * @param hook struct containing the information to hook the kernel function
 * @return int 0 on success, otherwise -EFAULT
 */
static int
_get_addr_of_orig_function(function_hook_t *hook)
{
    *(hook->orig_function) = _get_addr_by_name(hook->name);

    if (!(*(hook->orig_function))) {
        pr_info("Unable to resolve address of %s\n", hook->name);
        return -EFAULT;
    }

    return 0;
}


static int
register_function(function_hook_t *hook)
{
    int ret = 0;

    if (_get_addr_of_orig_function(hook)) {
        pr_info("Unable to obtain address of %s\n", hook->name);
        return -EFAULT;
    }

    //setup ftrace_ops struct used to register and later on unregister the function callback
    struct ftrace_ops *local_fops = &hook->fops;

    local_fops->func = ftrace_callback;

    local_fops->flags = 
            FTRACE_OPS_FL_SAVE_REGS //save registers and pass them to callback function ~> if not possible, callback will fail
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
            | FTRACE_OPS_FL_RECURSION //disable recursion protection
            #else
            | FTRACE_OPS_FL_RECURSION_SAFE
            #endif
            | FTRACE_OPS_FL_IPMODIFY; //required to modify the instruction pointer

    local_fops->private = hook->hook_function;

    if ((ret = ftrace_set_filter_ip(local_fops, *(hook->orig_function), 0, 0))) {
        pr_info("Unable to register hook for %s\n", hook->name);
        return ret;
    }

    if ((ret = register_ftrace_function(local_fops))) {
        pr_info("Unable to set filter on ftrace_ops struct for %s\n", hook->name);
        ftrace_set_filter_ip(&(hook->fops), *(hook->orig_function), 1, 0);
        return ret;
    }

    return ret;
}


static int
unregister_function(function_hook_t *hook)
{
    int ret = 0;

    if ((ret = unregister_ftrace_function(&(hook->fops)))) {
        pr_info("Unable to unregister hook function for %s\n", hook->name);
    }

    if ((ret = ftrace_set_filter_ip(&(hook->fops), *(hook->orig_function), 1, 0))) {
        pr_info("Unable to unregister2 hook function for %s\n", hook->name);
    }

    return ret;
}


int
undo_hooking(function_hook_t *hook_array, int size)
{
    int ret = 0;

    for (int i = size-1; i >= 0; i--) {
        ret = unregister_function(&hook_array[i]);

        if (ret != 0) break;
    }

    return ret;
}


int
do_hooking(function_hook_t *hook_array, int size)
{
    int ret = 0;

    for (int i = 0; i < size; i++) {
        ret = register_function(&hook_array[i]);

        if (ret != 0) {
            undo_hooking(hook_array, i);
            break;
        }
    }

    return ret;
}
