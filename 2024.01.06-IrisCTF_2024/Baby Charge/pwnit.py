#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("babycha.chal.irisc.tf", 10100)


def main():
    # See chacha_init()
    leak_off = 12 * 4
    leak_size = 2 * 4
    flag = b""
    with connect() as tube:
        tube.sendlineafter(b"> ", b"2")
        data = bytes.fromhex(tube.recvline().decode())
        flag_len = len(data)
    for i in range(0, flag_len, leak_size):
        with connect() as tube:
            tube.sendlineafter(b"> ", b"1")
            tube.sendlineafter(b"? ", b"A" * (leak_off - i))
            tube.recvline()
            tube.sendlineafter(b"> ", b"2")
            data = bytes.fromhex(tube.recvline().decode())
            flag += data[i : i + leak_size]
            print(flag)  # irisctf{initialization_is_no_problem}


if __name__ == "__main__":
    main()
