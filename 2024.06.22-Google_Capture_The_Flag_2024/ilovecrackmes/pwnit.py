#!/usr/bin/env python3
from pwn import *


def connect():
    tube = remote("ilovecrackmes.2024.ctfcompetition.com", 1337)
    assert tube.recvline() == b"== proof-of-work: disabled ==\n"
    return tube


def main():
    with connect() as tube:
        g, c = tube.recvline().split(b":")
        g = int(g, 16)
        n = g - 1
        c = int(c, 16)
        love = int(b"ilovecrackmes".hex(), 16) << 32
        answer = (c * pow(g, love, n ** 2)) % (n ** 2)
        tube.sendlineafter(b"> ", hex(answer)[2:])
        tube.interactive()
        # CTF{4r17hm371c_w17h0u7_d3cryp7i0n_f7w}


if __name__ == "__main__":
    main()
