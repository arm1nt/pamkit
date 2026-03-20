#ifndef PAMKIT_UTIL_USER_H
#define PAMKIT_UTIL_USER_H

#include "linux/err.h"
#include "linux/string.h"
#include "log.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static char *
get_string_from_usr(const char __user *str, const size_t max_size)
{
    char *kbuffer = strndup_user(str, max_size);
    if (IS_ERR(kbuffer)) {
        prerr_ratelimited("Failed to copy user string to kernel buffer");
        return NULL;
    }

    return kbuffer;
}

static int
copy_to_usr(void __user *target, const void *source, const size_t size)
{
    if (copy_to_user(target, source, size)) {
        prerr_ratelimited("Failed to copy data to user space");
        return -EFAULT;
    }

    return 0;
}

#endif /* PAMKIT_UTIL_USER_H */
