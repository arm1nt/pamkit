#!/usr/bin/awk -f

match($0, /SYSCALL_X\(([a-zA-Z0-9_]+),[ \t]*(__NR_[a-zA-Z0-9_]+)\)/, m) {
    name  = m[1]
    uname = toupper(name)

    printf "#define SYSCALL_ORIG_%s(regs, ...) ", uname
    printf "SYSCALL_ORIG_NAME(%s)(SYSCALL_ORIG_ARGS(regs, __VA_ARGS__))\n", name
}
