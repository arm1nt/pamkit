#ifndef _PAMKIT_LOG_H
#define _PAMKIT_LOG_H

#ifdef PAMKIT_LOGGING

#include <linux/module.h>

#define prinfo(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define prwarn(fmt, ...) pr_warn(fmt, ##__VA_ARGS__)
#define prerror(fmt, ...) pr_err(fmt, ##__VA_ARGS__)

#else

#define prinfo(fmt, ...) do {} while (0)
#define prwarn(fmt, ...) do {} while (0)
#define prerror(fmt, ...) do {} while (0)

#endif /* PAMKIT_LOGGING */

#endif /* _PAMKIT_LOG_H */
