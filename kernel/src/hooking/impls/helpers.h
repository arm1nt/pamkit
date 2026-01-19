#ifndef _PAMKIT_HELPERS_H
#define _PAMKIT_HELPERS_H

#include "../approach.h"
#include "../hooking.h"
#include "../../symbol_resolver.h"
#include "../../util/log.h"
#include "../../util/constants.h"

#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kprobes.h>

void pamkit_enable_write_protection(void);

void pamkit_disable_write_protection(void);

#endif /* _PAMKIT_HELPERS_H */
