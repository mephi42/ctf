#!/usr/bin/env python3
import struct
import capstone

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for i in range(65536):
    buf = struct.pack('>H', i) + b'\x90' * 14
    s = ''
    for insn in cs.disasm(buf, 0x200):
        if insn.mnemonic == 'nop':
            continue
        s += insn.mnemonic + ' ' + insn.op_str + '; '
    if s != '':
        print(s)
