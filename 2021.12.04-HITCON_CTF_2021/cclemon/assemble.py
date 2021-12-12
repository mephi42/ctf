#!/usr/bin/env python3
import struct

OPCODE_HALT = 128
OPCODE_NOP = 0
OPCODE_ADD = 1
OPCODE_SUB = 2
OPCODE_MUL = 3
OPCODE_DIV = 4
OPCODE_MOD = 5
OPCODE_POS = 6
OPCODE_NEG = 7
OPCODE_SHL = 8
OPCODE_SHR = 9
OPCODE_LT = 10
OPCODE_LE = 11
OPCODE_GT = 12
OPCODE_GE = 13
OPCODE_EQ = 14
OPCODE_NE = 15
OPCODE_IN = 16
OPCODE_BOR = 17
OPCODE_BXOR = 18
OPCODE_BAND = 19
OPCODE_BNOT = 20
OPCODE_LNOT = 21
OPCODE_POP = 22
OPCODE_DUP = 23
OPCODE_SWAP = 24
OPCODE_LOAD = 25
OPCODE_STORE = 26
OPCODE_CONST = 27
OPCODE_UNPACK = 28
OPCODE_ADDITEM = 29
OPCODE_GETITEM = 30
OPCODE_SETITEM = 31
OPCODE_DELITEM = 32
OPCODE_ADDATTR = 33
OPCODE_GETATTR = 34
OPCODE_SETATTR = 35
OPCODE_DELATTR = 36
OPCODE_ADDSLICE = 37
OPCODE_GETSLICE = 38
OPCODE_SETSLICE = 39
OPCODE_DELSLICE = 40
OPCODE_ADDGETTER = 41
OPCODE_GETGETTER = 42
OPCODE_SETGETTER = 43
OPCODE_DELGETTER = 44
OPCODE_ADDSETTER = 45
OPCODE_GETSETTER = 46
OPCODE_SETSETTER = 47
OPCODE_DELSETTER = 48
OPCODE_JZ = 49
OPCODE_JNZ = 50
OPCODE_JMP = 51
OPCODE_ARRAY = 52
OPCODE_DICTIONARY = 53
OPCODE_DEFINE = 54
OPCODE_KARG = 55
OPCODE_VARG = 56
OPCODE_VKARG = 57
OPCODE_CALL = 58
OPCODE_TAILCALL = 59
OPCODE_RETURN = 60
OPCODE_SELF = 61
OPCODE_SUPER = 62
OPCODE_CLASS = 63
OPCODE_MODULE = 64
OPCODE_TRY = 65
OPCODE_UNTRY = 66
OPCODE_THROW = 67
OPCODE_LOADEXC = 68

TABLE = {
    "const": ("BI", OPCODE_CONST),
    "module": ("BBI", OPCODE_MODULE),
    "store": ("BBB", OPCODE_STORE),
    "define": ("BBBBBI", OPCODE_DEFINE),
    "load": ("BBB", OPCODE_LOAD),
    "mul": ("B", OPCODE_MUL),
    "add": ("B", OPCODE_ADD),
    "mod": ("B", OPCODE_MOD),
    "dup": ("B", OPCODE_DUP),
    "return": ("B", OPCODE_RETURN),
    "array": ("BI", OPCODE_ARRAY),
    "self": ("B", OPCODE_SELF),
    "setattr": ("B", OPCODE_SETATTR),
    "lt": ("B", OPCODE_LT),
    "jz": ("BI", OPCODE_JZ),
    "getattr": ("B", OPCODE_GETATTR),
    "call": ("BB", OPCODE_CALL),
    "pop": ("B", OPCODE_POP),
    "jmp": ("BI", OPCODE_JMP),
    "gt": ("B", OPCODE_GT),
    "tailcall": ("BB", OPCODE_TAILCALL),
    "sub": ("B", OPCODE_SUB),
    "getitem": ("B", OPCODE_GETITEM),
    "setitem": ("B", OPCODE_SETITEM),
    "le": ("B", OPCODE_LE),
    "bxor": ("B", OPCODE_BXOR),
    "class": ("BBB", OPCODE_CLASS),
    "eq": ("B", OPCODE_EQ),
}


def parse_const(s):
    M_PREFIX = "<module '"
    M_SUFFIX = "'>"
    if s.startswith(M_PREFIX) and s.endswith(M_SUFFIX):
        return 'M', s[len(M_PREFIX):-len(M_SUFFIX)].encode() + b"\0"
    F_PREFIX = "<function '"
    F_SUFFIX = "'>"
    if s.startswith(F_PREFIX) and s.endswith(F_SUFFIX):
        return 'F', s[len(F_PREFIX):-len(F_SUFFIX)].encode() + b"\0"
    try:
        i = int(s)
    except ValueError:
        pass
    else:
        return 'I', struct.pack(">Q", i)
    return 'S', s.encode() + b"\0"


def assemble(fp, out):
    code = b""
    cpool = []
    for line in fp:
        offset, opcode_str, *args = line.split()
        try:
            comment_pos = args.index(";")
        except ValueError:
            comment = ""
        else:
            comment = " ".join(args[comment_pos + 1:])
            args = args[:comment_pos]
        format, opcode = TABLE[opcode_str]
        if opcode == OPCODE_CLASS:
            # don't do this :-)
            # printf("class %d %d\n", machine_fetch_code1(lemon), machine_fetch_code1(lemon));
            args[0], args[1] = args[1], args[0]
        for i, c in enumerate(format[1:]):
            if c in "BI":
                args[i] = int(args[i])
        if opcode == OPCODE_CONST:
            cpool.append((args[0], *parse_const(comment)))
        insn = struct.pack(">" + format, opcode, *args)
        print(str(len(code)) + ": " + str(insn) + " ; " + str(args))
        code += insn
    out.write(struct.pack(">I", len(code)))
    out.write(code)
    out.write(struct.pack(">I", len(cpool)))
    for i, t, v in cpool:
        out.write(struct.pack(">BB", i, ord(t)) + v)


def main():
    with open("cclemon.asm") as fp:
        with open("cclemon.bin", "wb") as asm_fp:
            assemble(fp, asm_fp)


if __name__ == "__main__":
    main()
