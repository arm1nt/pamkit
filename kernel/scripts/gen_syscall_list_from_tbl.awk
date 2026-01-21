#!/usr/bin/awk -f

# skip comments and empty lines
/^#/ || NF == 0 { next }

{
    name = $3
    print "SYSCALL_X(" name ", __NR_" name ")"
}
