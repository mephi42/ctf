#!/usr/bin/env python3
from pwn import *

tube = remote('95.216.233.106', 47071)
with open('mapping.txt', 'w') as fp:
    for i in range(256):
        if i == ord('\n'):
            continue
        for j in (0, 254, 255):
            tube.recvuntil('Please enter the secret key to encrypt the data with: ')
            tube.sendline(bytes((j,)) * 256)
            tube.recvuntil('Please enter the data that you would like to encrypt: ')
            tube.sendline(bytes((i,)))
            tube.recvuntil('Your encrypted message is: ')
            fp.write(str(i) + ' ' + str(j) + ' ' + base64.b64decode(tube.recvline()).hex() + '\n')
            fp.flush()
