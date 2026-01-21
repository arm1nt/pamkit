#!/usr/bin/awk -f

# Skip non-defines
$1 != "#define" { next }

# Match lines where the second field starts with __NR_
$2 ~ /^__NR_/ {
    name = substr($2, 6)

    # Filter out non-syscall definitions
    if (name == "syscalls") next
    if (name == "_UAPI_ASM_UNISTD_64_H") next

    print "SYSCALL_X(" name ", " $2 ")"
}
