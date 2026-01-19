#ifndef _PAMKIT_LOG_H
#define _PAMKIT_LOG_H

#ifdef DEBUG

#include <linux/module.h>

#include "constants.h"

#define prinfo(fmt, ...) pr_info(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prdebug(fmt, ...) pr_debug(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prwarn(fmt, ...) pr_warn(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prerr(fmt, ...) pr_err(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)

#define prinfo_ratelimited(fmt, ...) pr_info_ratelimited(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prdebug_ratelimited(fmt, ...) pr_debug_ratelimited(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prwarn_ratelimited(fmt, ...) pr_warn_ratelimited(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)
#define prerr_ratelimited(fmt, ...) pr_err_ratelimited(PROGRAM_NAME ": " fmt "\n", ##__VA_ARGS__)

#else

#define prinfo(fmt, ...) do {} while (0)
#define prdebug(fmt, ...) do {} while (0)
#define prwarn(fmt, ...) do {} while (0)
#define prerr(fmt, ...) do {} while (0)

#define prinfo_ratelimited(fmt, ...)  do {} while (0)
#define prdebug_ratelimited(fmt, ...) do {} while (0)
#define prwarn_ratelimited(fmt, ...) do {} while (0)
#define prerr_ratelimited(fmt, ...) do {} while (0)

#endif /* DEBUG */

#endif /* _PAMKIT_LOG_H */
