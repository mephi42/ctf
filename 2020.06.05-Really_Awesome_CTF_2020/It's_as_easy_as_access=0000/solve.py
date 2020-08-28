#!/usr/bin/env python3
from datetime import datetime, timedelta
import json

from pwn import *

tube = remote('95.216.233.106', 54854)
# tube = process(['./access.py'])
# token example
#           0 1 2 3 4 5 6 7 8 9 a b c d e f
#
# c0 (iv)  49ab3ca4f3da16d3c936834238f626d8
# c1       782475edac1a271991a86ae29c26bbc7
#           a c c e s s = 9 9 9 9 ; e x p i
# c2       313fe75743ab39f923b140060d0738ef
#           r y = n n n n n n n n n n p p p
tube.recvuntil(b'Your choice: ')
tube.sendline('1')
token = json.loads(tube.recvline().replace(b'\'', b'"'))['token']
expires_at = (datetime.today() + timedelta(days=1)).strftime('%s')
token = bytearray.fromhex(token)
for i, (have, want) in enumerate(zip('ry=' + expires_at[:8], 'access=0000')):
    token[0x10 + i] ^= ord(have) ^ ord(want)
tube.recvuntil(b'Your choice: ')
tube.sendline(b'2')
tube.recvuntil(b'Please enter your admin token: ')
tube.sendline(token[16:].hex())
tube.recvuntil(b'Please enter your token\'s initialization vector: ')
tube.sendline(token[:16].hex())
tube.interactive()
