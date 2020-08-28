#!/usr/bin/env python3
import struct
from typing import List, Type

import zstandard as zstd

PATH = 'challenge.mctf'
SYMTAB = {
    0x17: 'length_ok',
    0x3e: 'readline',
    0x5a: 'print_incorrect_length',
    0xa2: 'write_word',
}


class Arg:
    pass


class Reg(Arg):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


NULL_REG = Reg('null')
REGS = [
    NULL_REG,  # 0
    Reg('RX'),  # 1
    Reg('RY'),  # 2
    Reg('RZ'),  # 3
    Reg('RTRGT'),  # 4
    Reg('RSTAT'),  # 5
    Reg('RCALL'),  # 6
    NULL_REG,  # 7
    NULL_REG,  # 8
    NULL_REG,  # 9
    NULL_REG,  # 10
    NULL_REG,  # 11
    NULL_REG,  # 12
    NULL_REG,  # 13
    NULL_REG,  # 14
    NULL_REG,  # 15
]


class Mem(Arg):
    def __init__(self, space, offset):
        self.space = space
        self.offset = offset

    def __str__(self):
        if self.space:
            s = 'smain'
        else:
            s = 'sin'
        return s + ' [' + hex(self.offset) + ']'


class Imm(Arg):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        s = hex(self.value)
        sym = SYMTAB.get(self.value)
        if sym is not None:
            s += f' <{sym}>'
        return s


class Insn:
    def __init__(self, args, length):
        self.args = args
        self.length = length
        self.signed = False  # TODO

    def __str__(self):
        mnemonic = type(self).__name__.lower()
        if self.SIGN:
            mnemonic += ('s' if self.signed else 'u')
        return mnemonic + ' ' + ', '.join(map(str, self.args))


class Halt(Insn):
    ARGS = ''
    SIGN = False


class Noop(Insn):
    ARGS = ''
    SIGN = False


class Inc(Insn):
    ARGS = 'x'
    SIGN = True


class Dec(Insn):
    ARGS = 'x'
    SIGN = True


class Add(Insn):
    ARGS = 'xx'
    SIGN = True


class Sub(Insn):
    ARGS = 'xx'
    SIGN = True


class Mul(Insn):
    ARGS = 'xx'
    SIGN = True


class Div(Insn):
    ARGS = 'xx'
    SIGN = True


class Addc(Insn):
    ARGS = 'xx'
    SIGN = True


class Subc(Insn):
    ARGS = 'xx'
    SIGN = True


class Read(Insn):
    ARGS = 'x'
    SIGN = False


class Writ(Insn):
    ARGS = 'x'
    SIGN = False


class Cpy(Insn):
    ARGS = 'xx'
    SIGN = False


class Mcpy(Insn):
    ARGS = 'xxx'
    SIGN = False


class Icpy(Insn):
    ARGS = 'ix'
    SIGN = False


class Cmp(Insn):
    ARGS = 'xx'
    SIGN = False


class And(Insn):
    ARGS = 'xx'
    SIGN = False


class Or(Insn):
    ARGS = 'xx'
    SIGN = False


class Cmpl(Insn):
    ARGS = 'x'
    SIGN = False


class Lshf(Insn):
    ARGS = 'xx'
    SIGN = False


class Rshf(Insn):
    ARGS = 'xx'
    SIGN = True


class Push(Insn):
    ARGS = 'x'
    SIGN = False


class Pop(Insn):
    ARGS = 'x'
    SIGN = False


class Cflg(Insn):
    ARGS = ''
    SIGN = False


class Call(Insn):
    ARGS = 'xxx'
    SIGN = False


class Rtrn(Insn):
    ARGS = ''
    SIGN = False


class Rtrv(Insn):
    ARGS = ''
    SIGN = False


class Rtl(Insn):
    ARGS = 'xx'
    SIGN = False


class Rtr(Insn):
    ARGS = 'xx'
    SIGN = False


class Cip(Insn):
    ARGS = 'x'
    SIGN = False


class Bswp(Insn):
    ARGS = 'x'
    SIGN = False


class Jump(Insn):
    ARGS = ''
    SIGN = False


class Jzro(Insn):
    ARGS = ''
    SIGN = False


class Jequ(Insn):
    ARGS = ''
    SIGN = False


class Jlt(Insn):
    ARGS = ''
    SIGN = False


class Jgt(Insn):
    ARGS = ''
    SIGN = False


class Jcry(Insn):
    ARGS = ''
    SIGN = False


class Jinf(Insn):
    ARGS = ''
    SIGN = False


class Jse(Insn):
    ARGS = ''
    SIGN = False


class Jsf(Insn):
    ARGS = ''
    SIGN = False


class Czro(Insn):
    ARGS = ''
    SIGN = False


class Ccry(Insn):
    ARGS = ''
    SIGN = False


class Xor(Insn):
    ARGS = 'xx'
    SIGN = False


class Swap(Insn):
    ARGS = 'xx'
    SIGN = False


class Rcpt(Insn):
    ARGS = 'xx'
    SIGN = True


class Rcpf(Insn):
    ARGS = 'xx'
    SIGN = True


INSNS: List[Type[Insn]] = [
    Halt,  # 0x000
    Noop,  # 0x001
    Inc,  # 0x002
    Dec,  # 0x003
    Add,  # 0x004
    Sub,  # 0x005
    Mul,  # 0x006
    Div,  # 0x007
    Addc,  # 0x008
    Subc,  # 0x009
    Read,  # 0x00A
    Writ,  # 0x00B
    Cpy,  # 0x00C
    Mcpy,  # 0x00D
    Icpy,  # 0x00E
    Cmp,  # 0x00F
    And,  # 0x010
    Or,  # 0x011
    Cmpl,  # 0x012
    Lshf,  # 0x013
    Rshf,  # 0x014
    Push,  # 0x015
    Pop,  # 0x016
    Cflg,  # 0x017
    Call,  # 0x018
    Rtrn,  # 0x019
    Rtrv,  # 0x01a
    Rtl,  # 0x01b
    Rtr,  # 0x01c
    Cip,  # 0x01d
    Bswp,  # 0x01e
    Jump,  # 0x01f
    Jzro,  # 0x020
    Jequ,  # 0x021
    Jlt,  # 0x022
    Jgt,  # 0x023
    Jcry,  # 0x024
    Jinf,  # 0x025
    Jse,  # 0x026
    Jsf,  # 0x027
    None,  # 0x028
    None,  # 0x029
    None,  # 0x02a
    None,  # 0x02b
    None,  # 0x02c
    None,  # 0x02d
    None,  # 0x02e
    None,  # 0x02f
    Czro,  # 0x030
    None,  # 0x031
    None,  # 0x032
    None,  # 0x033
    Ccry,  # 0x034
    None,  # 0x035
    None,  # 0x036
    None,  # 0x037
    None,  # 0x038
    None,  # 0x039
    None,  # 0x03a
    None,  # 0x03b
    None,  # 0x03c
    None,  # 0x03d
    None,  # 0x03e
    None,  # 0x03f
    Xor,  # 0x040
    Swap,  # 0x041
    Rcpt,  # 0x042
    Rcpf,  # 0x043
]


def disasm(scode, ip):
    def_word, = struct.unpack('<H', scode[ip * 2:(ip + 1) * 2])
    opcode = def_word & 0x1ff
    assert opcode < len(INSNS), hex(opcode)
    cls = INSNS[opcode]
    aflgs = []
    n_regs = 0
    for arg_constraint in cls.ARGS:
        aflg = (def_word >> (14 - (len(aflgs) * 2))) & 3
        aflgs.append(aflg)
        if arg_constraint == 'x':
            if not (aflg & 2):
                n_regs += 1
        elif arg_constraint == 'i':
            assert (aflg & 2)
        else:
            raise NotImplementedError()
    arg_off = 1
    if n_regs == 0:
        reg_word = None
        reg_word_bit = None
    else:
        reg_word, = struct.unpack(
            '<H', scode[(ip + arg_off) * 2:(ip + arg_off + 1) * 2])
        arg_off += 1
        reg_word_bit = (4 - n_regs) * 4
    args = []
    for arg_constraint, aflg in zip(cls.ARGS, aflgs):
        if arg_constraint == 'x':
            if aflg & 2:
                arg_text, = struct.unpack(
                    '<H', scode[(ip + arg_off) * 2:(ip + arg_off + 1) * 2])
                args.append(Mem(aflg & 1, arg_text))
                arg_off += 1
            else:
                args.append(REGS[(reg_word >> (16 - reg_word_bit)) & 0xf])
                reg_word_bit += 4
        elif arg_constraint == 'i':
            arg_text, = struct.unpack(
                '<H', scode[(ip + arg_off) * 2:(ip + arg_off + 1) * 2])
            args.append(Imm(arg_text))
            arg_off += 1
        else:
            raise NotImplementedError()
    return cls(args, arg_off)


class Machine:
    def __init__(self):
        self.rx = 0
        self.ry = 0
        self.rz = 0
        self.rtrgt = 0
        self.rstat = 0  # fse
        self.rcall = 0
        self.rsk = 0
        self.rsr = 0
        self.ssk = bytearray(0x10000)
        self.sin = bytearray(0x10000)
        self.smain = bytearray(0x10000)
        self.scode = bytearray(0x10000)
        self.ip = 1
        image = open(PATH, 'rb').read()
        print(f'Original size: {len(image)}')
        assert image[:4] == b'mCTZ'
        image = zstd.ZstdDecompressor().decompress(image[4:])
        print(f'Decompressed size: {len(image)}')
        i = 0
        while i < len(image):
            if image[i] == 1:
                space = self.sin
            elif image[i] == 2:
                space = self.scode
            else:
                assert image[i] == 3, (i, image[i])
                space = self.smain
            i += 1
            length, = struct.unpack('<H', image[i:i + 2])
            i += 2
            space_data = image[i:i + length * 2]
            space[2:2 + length] = space_data
            if space is self.sin:
                print(f'SIN[{length * 2}]: ' + space_data.hex())
            elif space is self.scode:
                print(f'SCODE[{length * 2}]: (see below)')
            elif space is self.smain:
                print(f'SMAIN[{length * 2}]: ' + space_data.hex())
            else:
                raise NotImplementedError()
            i += length * 2
        assert i == len(image)

    def run(self):
        for _ in range(100):
            self.step()

    def step(self):
        insn = disasm(self.scode, self.ip)
        code = ' '.join(f'{b:02x}' for b in self.scode[self.ip * 2:(self.ip + insn.length) * 2])
        sym = SYMTAB.get(self.ip)
        if sym is not None:
            print(f'0x{self.ip:04x} <{sym}>:')
        print(f'0x{self.ip:04x}:       {code:24}    {insn}')
        self.ip += insn.length


Machine().run()
