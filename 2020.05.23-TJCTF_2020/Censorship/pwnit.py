#!/usr/bin/env python3
from pwn import *
io = remote('p1.tjctf.org', 8003)
x = io.recvline()
a, b = re.search(br'(\d+) \+ (\d+)', x).groups()
io.sendline(str(int(a) + int(b)))
io.interactive()
# [DEBUG] Received 0x3c bytes:
#     b'tjctf{TH3_1llum1n4ti_I5_R3aL}\r'
#     b'tjctf{[CENt sSORED]}            \n'
