#!/usr/bin/env python3
import struct

import z3

with open('rusty-bytecode.bin', 'rb') as fp:
    text = fp.read()
regs = [0] * 6
REG_NAMES = {
    0: 'r0',
    1: 'r1',
    2: 'r2',
    3: 'r3',
    4: 'pc',
    5: 'sp',
}
stack = [0] * 254
flag = []
solver = z3.Solver()
PC = 4
SP = 5
BLACKLIST = {0x14, 0x37, 0x61, 0x97, 0xb2, 0xba, 0xbe, 0xc9}
while True:
    pos = regs[PC] * 16
    opcode = text[pos]
    if opcode == 0:
        imm64, = struct.unpack('<Q', text[pos + 8:pos + 16])
        print(f'0x{regs[PC]:02x}: push 0x{imm64:x}')
        stack[regs[SP]] = imm64
        regs[SP] += 1
        regs[PC] += 1
    elif opcode == 1:
        rx = text[pos + 1]
        print(f'0x{regs[PC]:02x}: push {REG_NAMES[rx]}')
        stack[regs[SP]] = regs[rx]
        regs[SP] += 1
        regs[PC] += 1
    elif opcode == 2:
        rx = text[pos + 1]
        val = stack[regs[SP] - 1]
        print(f'0x{regs[PC]:02x}: pop {REG_NAMES[rx]} (= {val})')
        regs[SP] -= 1
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 3:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] + regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} += {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 4:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] - regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} -= {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 5:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] * regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} *= {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 7:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] ^ regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} ^= {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 8:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] & regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} &= {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 9:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] | regs[ry]
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} |= {REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 10:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] << (regs[ry] & 0xff)
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} <<= (char){REG_NAMES[ry]} (= {val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 11:
        rx = text[pos + 1]
        ry = text[pos + 2]
        val = regs[rx] >> (regs[ry] & 0xff)
        print(f'0x{regs[PC]:02x}: {REG_NAMES[rx]} >>= (char){REG_NAMES[ry]} (={val})')
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 12:
        rx = text[pos + 1]
        index = len(flag)
        flag_byte = z3.BitVec(f'f{index}', 8)
        val = z3.ZeroExt(56, flag_byte)
        print(f'0x{regs[PC]:02x}: getchar {REG_NAMES[rx]} (= {val})')
        solver.append(z3.Or(
            z3.And(flag_byte >= ord('a'), flag_byte <= ord('z')),
            z3.And(flag_byte >= ord('A'), flag_byte <= ord('Z')),
            z3.And(flag_byte >= ord('0'), flag_byte <= ord('9')),
            flag_byte == ord('_'),
            flag_byte == ord('.'),
            flag_byte == ord('{'),
            flag_byte == ord('}'),
        ))
        if index == 6:
            solver.append(z3.And(
                flag_byte != ord('c'),
                flag_byte != ord('r'),
                flag_byte != ord('A'),
                flag_byte != ord('B'),
                flag_byte != ord('P'),
                flag_byte != ord('Y'),
                flag_byte != ord('{'),
            ))
        if index == 7:
            solver.append(flag_byte != ord('c'))
        if index == 8:
            solver.append(flag_byte != ord('D'))
        if index == 15:
            solver.append(flag_byte != ord('.'))
        flag.append(flag_byte)
        regs[rx] = val
        regs[PC] += 1
    elif opcode == 13:
        rx = text[pos + 1]
        ry = text[pos + 2]
        cond = regs[rx] != regs[ry]
        pc_not_taken = regs[PC] + 1
        pc_taken = regs[PC] + 2
        print(f'0x{regs[PC]:02x}: if ({REG_NAMES[rx]} != {REG_NAMES[ry]}) pc = 0x{pc_taken:02x}')
        if cond is True:
            print('# always taken')
            regs[PC] = pc_taken
            solve = False
        elif cond is False:
            print('# always not taken')
            regs[PC] = pc_not_taken
            solve = False
        elif pc_not_taken in BLACKLIST:
            assert pc_taken not in BLACKLIST, hex(pc_not_taken)
            solver.append(cond)
            print(f'# {cond}')
            regs[PC] = pc_taken
            solve = True
        else:
            assert pc_taken in BLACKLIST, hex(pc_taken)
            cond = z3.Not(cond)
            print(f'# {cond}')
            solver.append(cond)
            regs[PC] = pc_not_taken
            solve = True
        if solve:
            result = str(solver.check())
            print(result)
            assert result == 'sat'
            model = solver.model()
            flag_bytes = bytearray()
            for flag_byte in flag:
                flag_byte_val = model[flag_byte]
                if flag_byte_val is None:
                    flag_bytes.append(b'?')
                else:
                    flag_bytes.append(int(str(flag_byte_val)))
            print(flag_bytes)
    elif opcode == 16:
        imm64, = struct.unpack('<Q', text[pos + 8:pos + 16])
        print(f'0x{regs[PC]:02x}: pc = 0x{imm64:02x}')
        regs[PC] = imm64
    elif opcode == 17:
        imm64, = struct.unpack('<Q', text[pos + 8:pos + 16])
        val = regs[PC] + imm64
        print(f'0x{regs[PC]:02x}: pc = 0x{val:02x}')
        regs[PC] = val
    elif opcode == 20:
        rx = text[pos + 1]
        val = regs[rx]
        print(f'0x{regs[PC]:02x}: putchar {REG_NAMES[rx]} (= {val})')
        regs[PC] += 1
    elif opcode == 21:
        print(f'0x{regs[PC]:02x}: hlt')
        break
    else:
        raise Exception(str(opcode))
# flag{whats_the_difference...}
