NAME := pamkit

obj-m := $(NAME).o

$(NAME)-y += init.o symbol_resolver.o util/read_table.o sys.o
$(NAME)-y += hooking/hooking.o hooking/impls/ftrace.o hooking/impls/syscall_table.o \
			hooking/impls/switch_patching.o hooking/impls/helpers.o
$(NAME)-y += net/net.o

ifeq ($(DEBUG_BUILD), 1)
	ccflags-y += -DDEBUG -g -O1
endif

ifeq ($(QEMU_BUILD), 1)
	SHARED_DIR ?= $(shell pwd)
	VM_IMAGE ?= ../resources/images/debian-13-nocloud-amd64.qcow2
endif

ifeq ($(CLANG_BUILD), 1)
	CC := clang
	LLVM := 1
endif

ifeq ($(CUSTOM_KERNEL), 1)
	TARGET_KERNEL ?= "linux-6.18.1"
	KERNEL_DIR := ../resources/custom-kernels/$(TARGET_KERNEL)
	KERNEL_IMAGE := $(KERNEL_DIR)/arch/x86_64/boot/bzImage
	SYSCALL_SRC := $(KERNEL_DIR)/arch/x86/entry/syscalls/syscall_64.tbl

	SYSCALL_LIST_AWK := ../scripts/gen_syscall_list_from_tbl.awk
else
	TARGET_KERNEL := $(shell uname -r)
	KERNEL_DIR := /lib/modules/$(TARGET_KERNEL)/build
	SYSCALL_SRC := $(KERNEL_DIR)/arch/x86/include/generated/uapi/asm/unistd_64.h

	SYSCALL_LIST_AWK := ../scripts/gen_syscall_list_from_unistd.awk
endif

SYSCALL_ORIG_AWK := ../scripts/gen_orig_syscall_macros.awk

# Automatically generated headers
SYSCALL_LIST_HDR := generated/syscall_list_x64.h
GEN_ORIG_SYSCALL_HDR := generated/syscall_orig_x64.h

# Specify the desired hooking approach
ifeq ($(FTRACE_HOOKING), 1)
	ccflags-y += -DPAMKIT_FTRACE_SYSCALL_HOOKING
else ifeq ($(SWITCH_PATCHING_HOOKING), 1)
	ccflags-y += -DPAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING
else ifeq ($(SYSCALL_TABLE_HOOKING), 1)
	ccflags-y += -DPAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING
endif

.PHONY: all qemu host clean qemu_deploy

default: all

$(shell mkdir -p generated)

$(SYSCALL_LIST_HDR): $(SYSCALL_SRC) $(SYSCALL_LIST_AWK)
	@echo "  GEN     $@ ($(BUILD_TARGET))"
	@echo "/* AUTO-GENERATED — DO NOT EDIT */" > $@
	@echo "/* Source: $(SYSCALL_SRC) */" >> $@
	@echo "" >> $@
	@echo "#include <asm/syscalls.h>" >> $@
	@echo "" >> $@
	@awk -f $(SYSCALL_LIST_AWK) $(SYSCALL_SRC) >> $@

$(GEN_ORIG_SYSCALL_HDR): $(SYSCALL_LIST_HDR) $(SYSCALL_ORIG_AWK)
	@echo "  GEN     $@ ($(BUILD_TARGET))"
	@echo "/* AUTO-GENERATED — DO NOT EDIT */" > $@
	@echo "" >> $@
	@echo "#ifndef _PAMKIT_SYSCALL_ORIG_X64_H" >> $@
	@echo "#define _PAMKIT_SYSCALL_ORIG_X64_H" >> $@
	@echo "" >> $@
	@echo "#include <asm/ptrace.h>" >> $@
	@echo "" >> $@
	@awk -f $(SYSCALL_ORIG_AWK) $(SYSCALL_LIST_HDR) >> $@
	@echo "" >> $@
	@echo "#endif /* _PAMKIT_SYSCALL_ORIG_X64_H */" >> $@

all: $(SYSCALL_LIST_HDR) $(GEN_ORIG_SYSCALL_HDR)
	@echo "Building module for $(TARGET_KERNEL)..."
	@make -C $(KERNEL_DIR) M=$(PWD) LLVM=$(LLVM) modules

compile_commands:
	@$(MAKE) -C $(KERNEL_DIR) M=$(PWD) LLVM=$(LLVM) compile_commands.json

host:
	@$(MAKE) all CUSTOM_KERNEL=0 DEBUG_BUILD=1 QEMU_BUILD=0

qemu:
	@$(MAKE) all CUSTOM_KERNEL=1 DEBUG_BUILD=1 QEMU_BUILD=1

qemu_deploy:
ifeq ($(CUSTOM_KERNEL), 1)
	@echo "Starting vm..."

	@virt-copy-in \
		-a $(VM_IMAGE) \
		../resources/scripts/mount_shared_folder.bash \
		/root

	@qemu-system-x86_64 \
		-m 8G \
		-smp 4 \
		-cpu host \
		-enable-kvm \
		-kernel $(KERNEL_IMAGE) \
		-drive file=$(VM_IMAGE),format=qcow2 \
		-append "root=/dev/sda1 console=ttyS0 nokaslr" \
		-virtfs local,path=$(SHARED_DIR),mount_tag=shared_mod,security_model=passthrough,id=shared_mod \
		-nographic \
		-s
else
	@echo "Please specify a custom kernel to compile the module against"
endif

clean:
	@echo "Doing cleanup..."
	@make -C $(KERNEL_DIR) M=$(PWD) clean
	$(RM) $(GEN_ORIG_SYSCALL_HDR) $(SYSCALL_LIST_HDR)
