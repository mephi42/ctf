#!/usr/bin/env python3
OP_DECREMENT = '🦔'
OP_FORWARD = '➡️'
OP_AND = '🍴'
OP_OR_A_R = '🎷'
OP_HALT = '🗿'
OP_JMP = '🐰'
OP_OUT = '📤'
OP_JNE = '🏷️'
OP_REWIND = '⏪'
OP_JE = '⚖️'
OP_CMP_R_0 = '❔'
OP_MOV_RJMP = '🐇'
OP_MOV_A_R = '🎁'
OP_MOV_A_I = '✉️'
OP_MOV_R_A = '📦'
OP_READ = '👁️'
TAPE0 = '📼'
TAPE1 = '🎞️'
TAPES = {
    'T0': TAPE0,
    'T1': TAPE1,
    'T2': '🎥',
}
REG_A = '🗃️'
REGS = {
    'X': '🔨',
    'Y': '⛏️',
    'A': REG_A,
}
REG_NAMES = {reg: reg_name for (reg_name, reg) in REGS.items()}
HEX = '😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏'


class Asm:
    def __init__(self):
        self.code = []
        self.pos = 0
        self.backpatch = {}
        self.labels = {}

    def get_offset(self):
        offset = 0
        for i in range(self.pos):
            offset += len(self.code[i])
        return offset

    def emit(self, x):
        if self.pos == len(self.code):
            self.code.append(x)
        else:
            self.code[self.pos] = x
        self.pos += 1

    def emit_hex(self, n):
        self.emit(HEX[n])

    def emit_byte(self, n):
        self.emit_hex(n >> 4)
        self.emit_hex(n & 0xf)

    def emit_half(self, n):
        self.emit_byte(n >> 8)
        self.emit_byte(n & 0xff)

    def emit_reg(self, reg):
        self.emit(REGS[reg])

    def emit_tape(self, tape):
        self.emit(TAPES[tape])

    def emit_read(self, tape):
        self.emit(OP_READ)
        self.emit_tape(tape)

    def emit_mov(self, dst, src):
        if src == 'A':
            self.emit(OP_MOV_R_A)
            self.emit_reg(dst)
        elif dst == 'A':
            if isinstance(src, int):
                self.emit(OP_MOV_A_I)
                self.emit_byte(src)
            else:
                self.emit(OP_MOV_A_R)
                self.emit_reg(src)
        elif dst == 'RJMP':
            self.emit(OP_MOV_RJMP)
            assert isinstance(src, str)
            self.backpatch[self.pos] = src
            self.emit_half(0)
        else:
            raise NotImplementedError()

    def emit_cmp(self, lhs, rhs):
        if rhs == 0:
            self.emit(OP_CMP_R_0)
            self.emit_reg(lhs)
        else:
            raise NotImplementedError()

    def emit_je(self):
        self.emit(OP_JE)

    def emit_rewind(self, tape):
        self.emit(OP_REWIND)
        self.emit_tape(tape)

    def emit_forward(self, tape):
        self.emit(OP_FORWARD)
        self.emit_tape(tape)

    def emit_decrement(self, reg):
        self.emit(OP_DECREMENT)
        self.emit_reg(reg)

    def emit_jne(self):
        self.emit(OP_JNE)

    def emit_out(self):
        self.emit(OP_OUT)

    def emit_jmp(self):
        self.emit(OP_JMP)

    def emit_halt(self):
        self.emit(OP_HALT)

    def emit_or(self, lhs, rhs):
        assert lhs == 'A'
        self.emit(OP_OR_A_R)
        self.emit_reg(rhs)

    def emit_and(self, lhs, rhs):
        assert lhs == 'A'
        self.emit(OP_AND)
        self.emit_reg(rhs)

    def emit_label(self, label):
        self.labels[label] = self.get_offset()

    def finalize(self):
        for pos, label in self.backpatch.items():
            self.pos = pos
            self.emit_half(self.labels[label])


class SimTape:
    def __init__(self):
        self.data = bytearray(256)
        self.pos = 0

    def read(self):
        return self.data[self.pos]


class Sim:
    def __init__(self, code):
        self.code = code
        self.tapes = {t: SimTape() for t in TAPES.values()}
        self.regs = {r: 0 for r in REGS}
        self.pc = 0
        self.rjmp = 0
        self.eq = False

    def run(self):
        while self.step():
            pass

    def match(self, v):
        if self.code[self.pc:self.pc + len(v)] == v:
            self.pc += len(v)
            return True
        return False

    def match_tape(self):
        for tape in TAPES.values():
            if self.match(tape):
                return tape
        assert False

    def match_reg(self):
        for reg in REGS.values():
            if self.match(reg):
                return reg
        assert False

    def match_hex(self):
        for v, hex in enumerate(HEX):
            if self.match(hex):
                return v
        assert False

    def match_byte(self):
        return (self.match_hex() << 4) | self.match_hex()

    def match_half(self):
        return (self.match_byte() << 8) | self.match_byte()

    def step(self):
        if self.match(OP_FORWARD):
            self.tapes[self.match_tape()].pos += 1
            return True
        if self.match(OP_READ):
            val = self.tapes[self.match_tape()].read()
            self.regs[REG_A] = val
            print(f'OP_READ: A=0x{val:02x}')
            return True
        if self.match(OP_MOV_R_A):
            reg = self.match_reg()
            val = self.regs[REG_A]
            self.regs[reg] = val
            print(f'OP_MOV_R_A: {REG_NAMES[reg]}=0x{val:02x}')
            return True
        if self.match(OP_OR_A_R):
            reg = self.match_reg()
            val = self.regs[REG_A] | self.regs[reg]
            self.regs[REG_A] = val
            print(f'OP_OR_A_R {REG_NAMES[reg]}: A=0x{val:02x}')
            return True
        if self.match(OP_MOV_A_I):
            self.regs[REG_A] = self.match_byte()
            return True
        if self.match(OP_MOV_RJMP):
            self.rjmp = self.match_half()
            return True
        if self.match(OP_DECREMENT):
            reg = self.match_reg()
            val = (self.regs[reg] - 1) & 0xff
            print(f'OP_DECREMENT: {REG_NAMES[reg]}=0x{val:02x}')
            self.regs[reg] = val
            return True
        if self.match(OP_CMP_R_0):
            self.eq = self.regs[self.match_reg()] == 0
            return True
        if self.match(OP_JNE):
            if not self.eq:
                self.pc = self.rjmp
            return True
        if self.match(OP_AND):
            self.regs[REG_A] &= self.regs[self.match_reg()]
            return True
        if self.match(OP_JE):
            if self.eq:
                self.pc = self.rjmp
            return True
        if self.match(OP_MOV_A_R):
            reg = self.match_reg()
            val = self.regs[reg]
            self.regs[REG_A] = val
            print(f'OP_MOV_A_R {REG_NAMES[reg]}: A=0x{val:02x}')
            return True
        if self.match(OP_OUT):
            print(f'OP_OUT: 0x{self.regs[REG_A]:02x}')
            return True
        if self.match(OP_JMP):
            self.pc = self.rjmp
            return True
        if self.match(OP_HALT):
            return False
        raise NotImplementedError(self.code[self.pc:])


asm = Asm()
asm.emit_label('loop0')
asm.emit_forward('T0')
asm.emit_forward('T1')
asm.emit_read('T0')  # a = t0
asm.emit_mov('X', 'A')  # x = t0
asm.emit_read('T1')  # a = t1
asm.emit_and('A', 'X')  # a = t0 & t1
asm.emit_mov('X', 'A')  # x = t0 & t1
asm.emit_mov('A', 0xff)  # a = 0xff
asm.emit_mov('Y', 'A')  # y = 0xff
asm.emit_mov('RJMP', 'sub')
asm.emit_label('sub')
asm.emit_decrement('Y')
asm.emit_decrement('X')
asm.emit_cmp('X', 0)
asm.emit_jne()  # y = 0xff - (t0 & t1) = ~(t0 & t1)
asm.emit_read('T0')  # a = t0
asm.emit_mov('X', 'A')  # x = t0
asm.emit_read('T1')  # a = t1
asm.emit_or('A', 'X')  # a = t0 | t1
asm.emit_and('A', 'Y')  # a = (t0 | t1) & ~(t0 & t1)
asm.emit_mov('X', 'A')  # x = t0 ^ t1
asm.emit_mov('RJMP', 'done')
asm.emit_cmp('X', 0)
asm.emit_je()
asm.emit_mov('A', 'X')
asm.emit_out()
asm.emit_mov('RJMP', 'loop0')
asm.emit_jmp()
asm.emit_label('done')
asm.emit_halt()
asm.finalize()
code = ''.join(asm.code)
print(code)
sim = Sim(code)
sim.tapes[TAPE0].data[:4] = b'\x01\x02\x03\x04'
sim.tapes[TAPE1].data[:4] = b'\x02\x03\x04\x05'
sim.run()
