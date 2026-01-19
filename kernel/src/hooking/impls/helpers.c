#include "helpers.h"

static inline void
cr0_reg_write(unsigned long cr0)
{
    long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

inline void
pamkit_enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    cr0_reg_write(cr0);
}

inline void
pamkit_disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    cr0_reg_write(cr0);
}
