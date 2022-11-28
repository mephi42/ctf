#!/usr/bin/env python3
from pwn import *


def main():
    with open("pwnit.js", "rb") as fp:
        js = fp.read()
    js = subprocess.check_output(["uglifyjs", "--mangle"], input=js)
    with open("pwnit.min.js", "wb") as fp:
        fp.write(js)
    magic = os.environ.get("MAGIC")
    if magic is not None:
        js = js.replace(b"0x73", magic.encode())
    with remote("35.227.151.88", 30262) as tube:
        tube.recvuntil(b"hashcash -mb25 ")
        challenge = tube.recvline().strip().decode()
        response = subprocess.check_output(["hashcash", "-mb25", challenge]).strip()
        tube.sendlineafter(b"hashcash token: ", response)
        tube.sendlineafter(
            b"Your javscript file size: ( MAX: 2000 bytes ) ", str(len(js)).encode()
        )
        tube.sendafter(b"Input your javascript file:", js)
        tube.interactive()


if __name__ == "__main__":
    main()
