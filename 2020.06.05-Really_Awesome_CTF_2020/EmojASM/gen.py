#!/usr/bin/env python3
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
        self.emit('😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏'[n])

    def emit_byte(self, n):
        self.emit_hex(n >> 4)
        self.emit_hex(n & 0xf)

    def emit_half(self, n):
        self.emit_byte(n >> 8)
        self.emit_byte(n & 0xff)

    def emit_reg(self, reg):
        self.emit({
            'X': '🔨',
            'Y': '⛏️',
            'A': '🗃️',
        }[reg])

    def emit_tape(self, tape):
        self.emit({
            'T0': '📼',
            'T1': '🎞️',
            'T2': '🎥',
        }[tape])

    def emit_read(self, tape):
        self.emit('👁️')
        self.emit_tape(tape)

    def emit_mov(self, dst, src):
        if src == 'A':
            self.emit('📦')
            self.emit_reg(dst)
        elif dst == 'RJMP':
            self.emit('🐇')
            assert isinstance(src, str)
            self.backpatch[self.pos] = src
            self.emit_half(0)
        else:
            raise NotImplementedError()

    def emit_cmp(self, lhs, rhs):
        if rhs == 0:
            self.emit('❔')
            self.emit_reg(lhs)
        else:
            raise NotImplementedError()

    def emit_je(self):
        self.emit('⚖️')

    def emit_rewind(self, tape):
        self.emit('⏪')
        self.emit_tape(tape)

    def emit_forward(self, tape):
        self.emit('➡️')
        self.emit_tape(tape)

    def emit_decrement(self, reg):
        self.emit('🦔')
        self.emit_reg(reg)

    def emit_jne(self):
        self.emit('🏷️')

    def emit_out(self):
        self.emit('📤')

    def emit_jmp(self):
        self.emit('🐰')

    def emit_halt(self):
        self.emit('🗿')

    def emit_label(self, label):
        self.labels[label] = self.get_offset()
    
    def finalize(self):
        for pos, label in self.backpatch.items():
            self.pos = pos
            self.emit_half(self.labels[label])



asm = Asm()
asm.emit_label('loop0')
asm.emit_forward('T1')
asm.emit_read('T1')
asm.emit_mov('X', 'A')
asm.emit_mov('RJMP', 'done')
asm.emit_cmp('X', 0)
asm.emit_je()
asm.emit_rewind('T0')
asm.emit_label('loop1')
asm.emit_forward('T0')
asm.emit_decrement('X')
asm.emit_mov('RJMP', 'loop1')
asm.emit_cmp('X', 0)
asm.emit_jne()
asm.emit_read('T0')
asm.emit_out()
asm.emit_mov('RJMP', 'loop0')
asm.emit_jmp()
asm.emit_label('done')
asm.emit_halt()
asm.finalize()
print(''.join(asm.code))
