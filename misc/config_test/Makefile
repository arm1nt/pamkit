#arm1nt - PAM-aware application that searches for its PAM config file in either a custom dir or in /etc/pam.d.

CC := gcc

DEFS := -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
CFLAGS := -std=c99 -pedantic -Wall -g $(DEFS)

.PHONY: clean

cdir: mod_test.c
	$(CC) $(CFLAGS) -o $@ -D CUSTOM_DIR mod_test.c -lpam -lpam_misc

ddir: mod_test.c
	$(CC) $(CFLAGS) -o $@ mod_test.c -lpam -lpam_misc

# Create a basic custom config file if it does not exist already
mod_test:
	touch ./mod_test
	echo "auth sufficient pam_unix.so" > mod_test

clean:
	rm cdir ddir
