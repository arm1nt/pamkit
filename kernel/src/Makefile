_TARGET_NAME := pamk1t
_OBJ_NAME := pamkit

obj-m += $(_TARGET_NAME).o
$(_TARGET_NAME)-objs := init.o hooking_framework.o sys.o read_table.o net.o ./hooking/hooking.o
SRC := $(_OBJ_NAME).c hooking_framework.c sys.c read_table.c net.c ./hooking/hooking.c

ccflags-y := -std=gnu99

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod ./$(_TARGET_NAME).ko

unload:
	sudo rmmod ./$(_TARGET_NAME).ko

reload:
	sudo rmmod ./$(_TARGET_NAME).ko
	make
	sudo insmod ./$(_TARGET_NAME).ko