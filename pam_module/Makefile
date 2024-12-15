CC := gcc

DEFS := -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
CFLAGS := -std=gnu99 -Wall -g $(DEFS)

.PHONY: all clean

all:
	gcc $(CFLAGS) -shared -fPIC -o pamkit_unix.so pamkit_unix.c -lpam

debug:
	gcc $(CFLAGS) -D DEBUG -shared -fPIC -o pamkit_unix.so pamkit_unix.c -lpam

clean:
	rm -f *.so
