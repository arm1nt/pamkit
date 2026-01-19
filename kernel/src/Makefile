NAME := pamkit

obj-m := $(NAME).o

$(NAME)-y += init.o symbol_resolver.o read_table.o sys.o
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
else
	TARGET_KERNEL := $(shell uname -r)
	KERNEL_DIR := /lib/modules/$(TARGET_KERNEL)/build
endif

# Specify the desired hooking approach
ifeq ($(FTRACE_HOOKING), 1)
	ccflags-y += -DPAMKIT_FTRACE_SYSCALL_HOOKING
else ifeq ($(SWITCH_PATCHING_HOOKING), 1)
	ccflags-y += -DPAMKIT_SWITCH_PATCHING_SYSCALL_HOOKING
else ifeq ($(SYSCALL_TABLE_HOOKING), 1)
	ccflags-y += -DPAMKIT_TABLE_OVERWRITE_SYSCALL_HOOKING
endif

.PHONY: all qemu host clean qemu_deploy

all:
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
