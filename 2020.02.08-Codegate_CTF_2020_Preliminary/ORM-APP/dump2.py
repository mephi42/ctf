#!/usr/bin/env python3
import os
import string
import struct

symbols = {
    0x0000008000000000: 'exit',
    0x0000008000000001: 'read',
    0x0000008000000046: 'do_read',
    0x000000800000009a: 'write',
    0x00000080000001f3: 'configure_device',
    0x0000008000000221: 'configure_devices',
    0x0000008000000281: 'atoi',
    0x0000008000000373: 'kinda_strlen_but_not_really',
    0x00000080000003b6: 'strlen',
    0x8080808080808000: 'entry',
    0x8080808080808013: 'get_project',
    0x808080808080805b: 'do_add',
    0x808080808080805c: '.Lincrement_n_projects',
    0x808080808080807d: '.L',
    0x80808080808081f0: 'do_show',
    0x8080808080808269: '.Lproject_not_found',
    0x808080808080828f: '.Lproject_found',
    0x80808080808082f0: '.Lskip_m',
    0x8080808080808382: 'do_migrate',
    0x80808080808083fb: '.Lproject_not_found',
    0x8080808080808421: '.Lincrement_n_projects',
    0x8080808080808442: '.L',
    0x8080808080808556: 'main',
    0x8080808080808601: '.Ladd',
    0x8080808080808614: '.Lshow',
    0x8080808080808627: '.Lmigrate',
    0x808080808080863a: '.Ldispatch',
    0x8080808080808644: 'do_bye',

    0x9090909090909080: 'str_bye',
    0x9090909090909090: 'str_name_prompt',
    0x90909090909090a8: 'str_description_prompt',
    0x90909090909090e8: 'str_project_saved',
    0x9090909090909110: 'str_index',
    0x9090909090909108: 'str_dot_newline',
    0x9090909090909118: 'str_project_not_found',
    0x9090909090909130: 'str_project',
    0x9090909090909140: 'str_m_mark',
    0x9090909090909148: 'str_newline',
    0x9090909090909150: 'str_arrows',
    0x9090909090909158: 'str_numbers',
    0x90909090909091a8: 'str_migrating',

    0xa0a0a0a0a0a0a000: 'user_input',
    0xa0a0a0a0a0a0b000: 'n_projects',
    0xa0a0a0a0a0a0b008: 'project_addresses',
    0xa0a0a0a0a0a0b048: 'projects',
}


# project layout:
# 0x00-0x08: name
# 0x08-0x88: description
# 0x88-0x90: migrated flag

def resolve(x):
    symbol = symbols.get(x)
    if symbol is None:
        return hex(x)
    else:
        return symbol


xstk = 0
xonly_0 = 1
xopsel = 2
yreg_or_imm = 3
ystk_or_reg = 4
yonly_0 = 5
yopsel = 6
yany = 7
alwaysimm = 8

opcodes = [
    ('exit',),
    ('push', xstk, yreg_or_imm),
    ('pop', xstk, yonly_0),
    (('neg', 'not'), xstk, yopsel),
    ('add', xstk, ystk_or_reg),
    ('sub', xstk, ystk_or_reg),
    ('mul', xstk, ystk_or_reg),
    ('div', xstk, ystk_or_reg),
    ('mod', xstk, ystk_or_reg),
    ('shr', xstk, ystk_or_reg),
    ('sar', xstk, ystk_or_reg),
    ('shl', xstk, ystk_or_reg),
    ('and', xstk, ystk_or_reg),
    ('or', xstk, ystk_or_reg),
    ('xor', xstk, ystk_or_reg),
    ('eq', xstk, ystk_or_reg),
    ('ne', xstk, ystk_or_reg),
    ('gtu', xstk, ystk_or_reg),
    ('gteu', xstk, ystk_or_reg),
    ('gt', xstk, ystk_or_reg),
    ('gte', xstk, ystk_or_reg),
    ('jmp', xonly_0, yany),
    ('jz', xstk, yany),
    ('jnz', xstk, yany),
    ('peek', xstk, yonly_0),
    (('write', 'read'), xopsel, ystk_or_reg),
    (('call', 'ret'), xopsel, yany),
    (('stabsb', 'stabsw', 'stabsd', 'stabsq'), xstk, yopsel, alwaysimm),
    (('stb', 'stw', 'std', 'stq'), xstk, yopsel),
    (('ldb', 'ldw', 'ldd', 'ldq'), xstk, yopsel),
]


def disasm(addr, data):
    i = 0
    while i < len(data):
        insn_addr = addr + i
        symbol = symbols.get(insn_addr)
        if symbol is not None:
            print(f'\n{symbol}:')
        insn_byte = data[i]
        opcode = insn_byte >> 3
        x = (insn_byte >> 2) & 1
        y = insn_byte & 3
        i += 1
        spec = opcodes[opcode]
        mnemonic = spec[0]
        text = ''
        if len(spec) > 1:
            if spec[1] == xstk:
                text += f' stk{x}'
            elif spec[1] == xonly_0:
                assert x == 0
            elif spec[1] == xopsel:
                mnemonic = mnemonic[x]
            else:
                raise Exception()
        if len(spec) > 2:
            if spec[2] == yreg_or_imm:
                if y == 0:
                    text += ' ' + resolve(struct.unpack('<Q', data[i:i + 8])[0])
                    i += 8
                else:
                    assert y == 3
                    text += ' reg'
            elif spec[2] == ystk_or_reg:
                if y == 1:
                    text += ' stk0'
                elif y == 2:
                    text += ' stk1'
                else:
                    assert y == 3
                    text += ' reg'
            elif spec[2] == yonly_0:
                assert y == 0
            elif spec[2] == yopsel:
                mnemonic = mnemonic[y]
            elif spec[2] == yany:
                if y == 0:
                    text += ' ' + resolve(struct.unpack('<Q', data[i:i + 8])[0])
                    i += 8
                elif y == 1:
                    text += ' stk0'
                elif y == 2:
                    text += ' stk1'
                else:
                    assert y == 3
                    text += ' reg'
            else:
                raise Exception()
        if len(spec) > 3:
            if spec[3] == alwaysimm:
                text += ' ' + resolve(struct.unpack('<Q', data[i:i + 8])[0])
                i += 8
            else:
                raise Exception()
        if len(text) == 0:
            text = mnemonic
        else:
            text = f'{mnemonic}{text}'
        print(f'0x{insn_addr:016x}: {text}')


def hexdump_line(addr, data):
    line = f'0x{addr:016x}:'
    ascii = ''
    for i in range(16):
        if i == 8:
            line += ' '
        if i < len(data):
            line += f' {data[i]:02x}'
            c = chr(data[i])
        else:
            line += ' --'
            c = '-'
        if c in string.whitespace:
            c = ' '
        elif c not in string.printable:
            c = '.'
        ascii += c
    print(line + ' | ' + ascii)


def hexdump(addr, data):
    all0_n = 0
    last_i = (len(data) - 1) // 16 * 16
    for i in range(0, len(data), 16):
        data_line = data[i:i + 16]
        if i != last_i and all(b == 0 for b in data_line):
            all0_n += 1
            if all0_n > 1:
                continue
        else:
            if all0_n > 1:
                print('...')
            all0_n = 0
        hexdump_line(addr + i, data_line)


with open('chal.ormb', 'rb') as fp:
    magic, word_size, entry, aux_size, count = struct.unpack('<IIQII', fp.read(0x18))
    print('Header:')
    print(f'magic    : 0x{magic:08x}')
    print(f'word_size: 0x{word_size:08x}')
    print(f'entry    : 0x{entry:016x}')
    print(f'aux_size : 0x{aux_size:08x}')
    print(f'count    : 0x{count:08x}')
    assert word_size == 8
    for i in range(count):
        addr, virt_size, file_size, prot = struct.unpack('<QQII', fp.read(0x18))
        print(f'Section #{i}')
        print(f'addr     : 0x{addr:016x}')
        print(f'virt_size: 0x{virt_size:016x}')
        print(f'file_size: 0x{file_size:08x}')
        print(f'prot     : 0x{prot:08x}')
        data = fp.read(file_size)
        if prot & 0x4:
            disasm(addr, data)
        else:
            hexdump(addr, data)
    assert fp.tell() == os.fstat(fp.fileno()).st_size
