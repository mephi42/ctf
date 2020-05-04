import os
import re
import struct
import time

import z3

FIRST_CHECKER_SIG = re.compile(re.escape(
    b'\xe0\xff\xbd\x27'
    b'\x1c\x00\xbf\xaf'
    b'\x18\x00\xbe\xaf'
    b'\x25\xf0\xa0\x03'
    b'\x20\x00\xc4\xaf'
    b'\x20\x00\xc4\x8f'
) + b'(.{4})' + re.escape(
    b'\x00\x00\x00\x00'
    b'\x25\xe8\xc0\x03'
    b'\x1c\x00\xbf\x8f'
    b'\x18\x00\xbe\x8f'
    b'\x20\x00\xbd\x27'
    b'\x08\x00\xe0\x03'
    b'\x00\x00\x00\x00'
), re.DOTALL)
RET_SIG = b'\x08\x00\xe0\x03\x00\x00\x00\x00'
AVOID_SIG = b'\x25\x10\x00\x00'
LAST_CHECKER = (
    b'\xf8\xff\xbd\x27'
    b'\x04\x00\xbe\xaf'
    b'\x25\xf0\xa0\x03'
    b'\x08\x00\xc4\xaf'
    b'\x01\xc0\x02\x3c'
    b'\xbe\xba\x42\x34'
    b'\x25\xe8\xc0\x03'
    b'\x04\x00\xbe\x8f'
    b'\x08\x00\xbd\x27'
    b'\x08\x00\xe0\x03'
    b'\x00\x00\x00\x00'
)
BASE = 0x400000
VERBOSE = False


def is_jal(insn):
    return insn & 0xfc000000 == 0x0c000000


def get_jal_target_pc(image, off):
    jal, = struct.unpack('<I', image[off:off + 4])
    assert is_jal(jal)
    jal_arg = jal & 0x03ffffff
    jal_target = ((BASE + off) & 0xf0000000) + (jal_arg << 2)
    return jal_target


def find_first_checker_pc(image):
    m, = list(re.finditer(FIRST_CHECKER_SIG, image))
    return get_jal_target_pc(image, m.start(1))


def decode_st(insn):
    s = (insn >> 21) & 0x1f
    t = (insn >> 16) & 0x1f
    return s, t


def decode_sti(insn):
    s = (insn >> 21) & 0x1f
    t = (insn >> 16) & 0x1f
    i = insn & 0xffff
    if i & 0x8000:
        i -= 0x10000
    return s, t, i


def decode_d(insn):
    d = (insn >> 11) & 0x1f
    return d,


def decode_std(insn):
    s = (insn >> 21) & 0x1f
    t = (insn >> 16) & 0x1f
    d = (insn >> 11) & 0x1f
    return s, t, d


def decode_stdh(insn):
    s = (insn >> 21) & 0x1f
    t = (insn >> 16) & 0x1f
    d = (insn >> 11) & 0x1f
    h = (insn >> 6) & 0x1f
    return s, t, d, h


class Sim:
    def __init__(self, pc0, avoid_pc, insns):
        self.pc0 = pc0
        self.avoid_pc = avoid_pc
        self.insns = insns
        self.pc = self.pc0
        self.regs = [0] * 32
        self.regs[4] = 0x1800  # a0
        self.regs[29] = 0x1000  # sp
        self.lo = 0
        self.mem = [0] * 0x2000
        self.x = [
            z3.BitVec('x0', 8),
            z3.BitVec('x1', 8),
            z3.BitVec('x2', 8),
            z3.BitVec('x3', 8),
        ]
        self.mem[0x1800:0x1804] = self.x
        self.solver = z3.Solver()

    def sw(self, addr, val):
        for i in range(4):
            self.mem[addr + i] = (val >> (i * 8)) & 0xff

    def lw(self, addr):
        val = 0
        for i in range(4):
            val |= self.mem[addr + i] << (i * 8)
        return val

    def step(self):
        insn_idx = (self.pc - self.pc0) >> 2
        insn = self.insns[insn_idx]
        op0 = insn >> 26
        if op0 == 0b001001:
            # addiu
            s, t, i = decode_sti(insn)
            self.regs[t] = self.regs[s] + i
            self.pc += 4
        elif op0 == 0b101011:
            # sw
            s, t, i = decode_sti(insn)
            self.sw(self.regs[s] + i, self.regs[t])
            self.pc += 4
        elif op0 == 0b000000:
            op1 = insn & 0b111111
            if op1 == 0b100101:
                # or
                s, t, d = decode_std(insn)
                self.regs[d] = self.regs[s] | self.regs[t]
                self.pc += 4
            elif op1 == 0b000000:
                # sll
                s, t, d, h = decode_stdh(insn)
                self.regs[d] = self.regs[t] << h
                self.pc += 4
            elif op1 == 0b100110:
                # xor
                s, t, d = decode_std(insn)
                self.regs[d] = self.regs[s] ^ self.regs[t]
                self.pc += 4
            elif op1 == 0b100001:
                # addu
                s, t, d = decode_std(insn)
                self.regs[d] = self.regs[s] + self.regs[t]
                self.pc += 4
            elif op1 == 0b011000:
                # mult
                s, t = decode_st(insn)
                self.lo = self.regs[s] * self.regs[t]
                self.pc += 4
            elif op1 == 0b010010:
                # mflo
                d, = decode_d(insn)
                self.regs[d] = self.lo
                self.pc += 4
            elif op1 == 0b100011:
                # subu
                s, t, d = decode_std(insn)
                self.regs[d] = (self.regs[s] - self.regs[t]) & 0xffffffff
                self.pc += 4
            elif op1 == 0b101010:
                # slt
                s, t, d = decode_std(insn)
                self.regs[d] = z3.If(
                    self.regs[s] < self.regs[t],
                    z3.BitVecVal(1, 31),
                    z3.BitVecVal(0, 31),
                )
                self.pc += 4
            else:
                raise Exception((hex(self.pc), hex(insn), bin(op0), bin(op1)))
        elif op0 == 0b100011:
            # lw
            s, t, i = decode_sti(insn)
            self.regs[t] = self.lw(self.regs[s] + i)
            self.pc += 4
        elif op0 == 0b100100:
            # lbu
            s, t, i = decode_sti(insn)
            addr = self.regs[s] + i
            val = self.mem[addr]
            if not isinstance(val, int):
                val = z3.ZeroExt(24, val)
            self.regs[t] = val
            self.pc += 4
        elif op0 == 0b000001 or op0 == 0b000101 or op0 == 0b000100:
            s, t, i = decode_sti(insn)
            assert self.insns[insn_idx + 1] == 0  # nop @ delay slot
            pc_then = self.pc + 4 + (i << 2)
            pc_else = self.pc + 4
            if op0 == 0b000101:
                # bne
                cond_for_else = self.regs[s] == self.regs[t]
            elif op0 == 0b000100:
                # beq
                cond_for_else = self.regs[s] != self.regs[t]
            elif op0 == 0b000001:
                if t == 0b00001:
                    # bgez
                    if (s == 2 and
                            self.insns[insn_idx + 2] == 0x00021023 and
                            pc_then == self.pc + 12):
                        self.regs[2] = z3.If(self.regs[2] & 0x80000000 == 0, self.regs[2], 0x100000000 - self.regs[2])
                        self.pc = pc_then
                        return None
                    else:
                        assert False
                else:
                    assert False
            else:
                assert False
            assert pc_then == self.avoid_pc
            if cond_for_else is False:
                assert False, 'Impossible'
            elif cond_for_else is True:
                self.pc = pc_else
            else:
                self.solver.add(cond_for_else)
                self.pc = pc_else
        elif op0 == 0b000011:
            # jal
            i = insn & 0x3ffffff
            assert str(self.solver.check()) == 'sat'
            model = self.solver.model()
            answer = bytes(model[x].as_long() for x in self.x)
            pc_next = (self.pc & 0xf0000000) + (i << 2)
            return answer, pc_next
        elif op0 == 0b001100:
            # andi
            s, t, i = decode_sti(insn)
            assert i >= 0
            self.regs[t] = self.regs[s] & i
            self.pc += 4
        else:
            raise Exception((hex(self.pc), hex(insn), bin(op0)))
        return None


def solve_checker(image, start_pc, checker_id):
    if VERBOSE:
        print(f'checker start: 0x{start_pc:x}')
    start_off = start_pc - BASE
    end_off = image.index(RET_SIG, start_off) + len(RET_SIG)
    end_pc = end_off + BASE
    if VERBOSE:
        print(f'checker end: 0x{end_pc:x}')
    code = image[start_off:end_off]
    if code == LAST_CHECKER:
        return None, None
    n_insns = (end_off - start_off) // 4
    avoid_off = image.index(AVOID_SIG, start_off)
    assert image.find(AVOID_SIG, avoid_off + 1, end_off) == -1
    avoid_pc = BASE + avoid_off
    sim = Sim(start_pc, avoid_pc, struct.unpack('<' + 'I' * n_insns, code))
    while True:
        solution = sim.step()
        if solution is not None:
            return solution


def solve(image, sample_id):
    i = 0
    first_checker_pc = find_first_checker_pc(image)
    checker_pc = first_checker_pc
    answer = b''
    while True:
        if VERBOSE:
            print(f'b *0x{checker_pc:x}')
        chunk, checker_pc = solve_checker(image, checker_pc, f'{sample_id}.{i}')
        if checker_pc is None:
            return answer
        answer += chunk
        i += 1


if __name__ == '__main__':
    for sample_id in sorted(os.listdir('samples')):
        with open(f'samples/{sample_id}', 'rb') as fp:
            image = fp.read()
        t0 = time.time()
        solution = solve(image, sample_id)
        t = time.time() - t0
        print(f'{sample_id}: {solution.hex()} t={t:2f}')
