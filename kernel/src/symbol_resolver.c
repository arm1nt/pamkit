#include "symbol_resolver.h"

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include "util/constants.h"
#include  "util/log.h"

typedef uintptr_t (*pamkit_kallsyms_lookup_name_t)(const char *name);

static pamkit_kallsyms_lookup_name_t pamkit_kallsyms_lookup_name = NULL;

/* Since kernel version 5.7.0 the kernel no longer exports 'kallsyms_lookup_name', i.e. the symbol cannot be linked in an OOT module */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)

#include <linux/kallsyms.h>

static inline int
_get_kallsyms_lookup_name_addr(void)
{
    pamkit_kallsyms_lookup_name = (pamkit_kallsyms_lookup_name_t) &kallsyms_lookup_name;
    prdebug("Found 'kallsyms_lookup_name' at 0x%px", (void*) pamkit_kallsyms_lookup_name);
    return PAMKIT_GENERIC_SUCCESS;
}

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)) && defined(CONFIG_KPROBES) /* version >= 5.7.0 but kprobes supported */

static int
_get_kallsyms_lookup_name_addr(void)
{
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    if (register_kprobe(&kp) != 0) {
        prerr("Failed to register kprobe");
        return PAMKIT_GENERIC_ERROR;
    }

    pamkit_kallsyms_lookup_name = (pamkit_kallsyms_lookup_name_t) kp.addr;

    if (!pamkit_kallsyms_lookup_name) {
        prerr("Failed to get 'kallsyms_lookup_name' address from kprobe");
        return PAMKIT_GENERIC_ERROR;
    }

    prdebug("Found 'kallsyms_lookup_name' at 0x%px", (void *) pamkit_kallsyms_lookup_name);
    unregister_kprobe(&kp);

    return PAMKIT_GENERIC_SUCCESS;
}

#else /* version > 5.7.0 and kernel not configured to support kprobes */

static inline int
_get_kallsyms_lookup_name_addr(void)
{
    return PAMKIT_GENERIC_ERROR;
}

#endif

static inline unsigned long
get_kernel_text_region_base_addr(void)
{
    /**
     * The kernel's '.text' region base addr cannot be hardcoded, a.o. because of KASLR it differs
     * between boots.
     * There is no guarantee that the difference between symbols will be the same across different systems,
     * so this computes an estimation of the base addr.
     */

    const uintptr_t symbol_addr = (uintptr_t) &sprint_symbol;
    const unsigned long mask = ~0x1FFFFFUL;
    const uintptr_t base_addr = symbol_addr & mask;
    prinfo("Estimated kernel '.text' region base address: 0x%px", (void *) base_addr);
    return base_addr;
}

static inline bool
is_kallsyms_lookup_name_symbol(char *name)
{
    const char *symbol_name = "kallsyms_lookup_name+0x0/0xd0";
    return strncmp(name, symbol_name, strlen(symbol_name)) == 0;
}

static int
generic_get_kallsyms_lookup_name_addr(void)
{
    char *name_buffer = kzalloc(KSYM_SYMBOL_LEN * sizeof(char), GFP_KERNEL);
    if (!name_buffer) {
        prerr("Failed to allocate memory for the name buffer in 'generic_get_kallsyms_lookup_name_addr'!");
        return PAMKIT_GENERIC_ERROR;
    }

    unsigned long kaddr = get_kernel_text_region_base_addr();

    for (size_t i = 0x00; i < 0x100000; i++) {

        if (!virt_addr_valid(kaddr)) {
            prdebug("Encountered invalid address 0x%px in 'generic_get_kallsyms_lookup_name_addr'", (void *) kaddr);
            kaddr += 0x10;
            continue;
        }

        sprint_symbol(name_buffer, kaddr);
        if (is_kallsyms_lookup_name_symbol(name_buffer)) {
            pamkit_kallsyms_lookup_name = (pamkit_kallsyms_lookup_name_t) kaddr;
            prdebug("Found 'kallsyms_lookup_name' at 0x%px", (void *) pamkit_kallsyms_lookup_name);
            kfree(name_buffer);
            return PAMKIT_GENERIC_SUCCESS;
        }

        kaddr += 0x10;
    }

    prdebug("Bruteforce search did not find the 'kallsyms_lookup_name' addr");
    kfree(name_buffer);

    return PAMKIT_GENERIC_ERROR;
}

int
init_symbol_resolver(void)
{
    int res;

    if ((res = _get_kallsyms_lookup_name_addr()) == PAMKIT_GENERIC_SUCCESS) {
        prdebug("Successfully initialized the symbol resolver");
        return res;
    }

    /* Fall back to a bruteforce searching approach */
    prdebug("Falling back to a generic bruteforce search to initialize the symbol resolver");

    if ((res = generic_get_kallsyms_lookup_name_addr()) == PAMKIT_GENERIC_SUCCESS) {
        prdebug("Successfully initialized the symbol resolver");
        return res;
    }

    prerr("Initialization of symbol resolver failed!");
    return PAMKIT_GENERIC_ERROR;
}

void *
pamkit_lookup_symbol_addr(const char *symbol_name)
{
    if (unlikely(pamkit_kallsyms_lookup_name == NULL)) {
        prwarn("Symbol resolver not initialized!");
        return NULL;
    }

    void *result = (void *) pamkit_kallsyms_lookup_name(symbol_name);
    prdebug("Resolved symbol '%s' to address: 0x%px", symbol_name, result);
    return result;
}
