#!/usr/bin/env python3
import os

path = os.path.expanduser('~/myrepos/libc-database/db/libc6_2.31-4_amd64.symbols')
base = 0x7ffff7ae5000
with open(path) as fp:
    for line in fp:
        name, address = line.split()
        address = base + int(address, 16)
        print(f'del_items(0x{address:x})')
        print(f'set_name(0x{address:x}, \'{name}@LIBC\')')
