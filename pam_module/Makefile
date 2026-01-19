CC := gcc

CFLAGS := -std=gnu99 -Wall -pedantic -O2
CFLAGS += -D_GNU_SOURCE

ifeq ($(DEBUG_BUILD), 1)
	CFLAGS += -DDEBUG
endif

SO_FLAGS := -shared -fPIC

.PHONY: all clean

all:
	@echo "Building mitm pam_unix module..."
	$(CC) $(CFLAGS) $(SO_FLAGS) -o pamkit_unix.so pamkit_unix.c -lpam

clean:
	@echo "Cleaning up..."
	@rm -f *.so
