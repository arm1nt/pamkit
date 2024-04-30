#arm1nt - Compile man-in-the-middle PAM module

CC := gcc

DEFS := -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
CFLAGS := -std=gnu99 -Wall -g $(DEFS)

all:
	gcc $(CFLAGS) -shared -fPIC -o pamkit_unix.so pamkit_unix.c -lpam

clean:
	rm -f *.so
