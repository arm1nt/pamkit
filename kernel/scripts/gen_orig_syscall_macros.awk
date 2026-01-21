#!/usr/bin/awk -f

# Match lines like: SYSCALL_X(name, __NR_name)
match($0, /SYSCALL_X\(([a-zA-Z0-9_]+),[ \t]*(__NR_[a-zA-Z0-9_]+)\)/, m) {
    name = m[1]
    printf "#define SYSCALL_ORIG_%-40s SYSCALL_ORIG_%-40s\n", name, toupper(name)
    printf "#define SYSCALL_ORIG_%-40s SYSCALL_ORIG_NAME(%s)(pt_regs)\n", toupper(name), name
}
