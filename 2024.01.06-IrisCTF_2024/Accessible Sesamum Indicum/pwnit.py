#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("accessible-sesasum-indicum.chal.irisc.tf", 10104)


def main():
    magic = bytes(de_bruijn(b"0123456789abcdef", 4))
    with connect() as tube:
        for _ in range(16):
            tube.sendlineafter(b"Attempt>", magic)
        # irisctf{de_bru1jn_s3quenc3s_c4n_mass1vely_sp33d_up_bru7e_t1me_f0r_p1ns}
        tube.interactive()


if __name__ == "__main__":
    main()
