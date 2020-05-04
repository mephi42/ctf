#!/usr/bin/env python3
import z3
from z3.z3util import get_vars, substitute


def as_number(bv):
    if not isinstance(bv, list):
        return bv
    n = 0
    for b in reversed(bv):
        n = (n << 1) | b
    return n


def ite(c, x, y):
    if c is True:
        return x
    elif c is False:
        return y
    else:
        if isinstance(x, int):
            x = z3.BitVecVal(x, 16)
        if isinstance(y, int):
            y = z3.BitVecVal(y, 16)
        return z3.If(c, x, y)


#user_input = [z3.BitVec(f'u{i}', 4) for i in range(17)]
#user_input[0] = 0
#user_input[1] = 9
#user_input[16] = 0
user_input = [0, 9, 15, 2, 1, 4, 3, 8, 10, 5, 13, 11, 14, 6, 7, 12, 0]
mem = [[], []] + user_input + [
    [1],
    [1],
    [0, 1, 0, 1],
    [1],
    [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1], [1], [1, 0, 1],
    [1, 1, 1], [1, 0, 1], [], [0, 1], [1], [1, 0, 1], [1], [1, 0, 1], [0, 0, 0, 1], [0, 1],
    [1, 0, 1], [0, 0, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1], [1, 0, 1],
    [0, 0, 1, 0, 0, 1], [0, 1], [1], [1, 0, 1], [0, 1, 0, 1], [0, 0, 0, 1], [1], [],
    [0, 0, 0, 1], [1], [1], [], [1], [1, 0, 1], [1], [1, 1, 1], [1, 0, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 1, 0, 0, 1, 1, 1], [1, 0, 1], [1],
    [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1, 1, 0, 1], [], [1, 1, 1], [1], [1],
    [1, 0, 1], [1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 1, 1, 0, 1], [1], [1, 0, 0, 1],
    [1, 0, 1], [1], [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 1], [0, 1, 1, 1],
    [0, 0, 1, 0, 1, 0, 1, 1, 0, 1], [0, 1, 1, 1], [0, 0, 0, 0, 0, 1, 1, 0, 1, 1], [0, 1],
    [0, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 0, 0, 1, 1],
    [1], [1, 0, 0, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 1],
    [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 0, 0, 1, 1], [0, 1, 1, 1],
    [0, 0, 0, 0, 0, 1, 1, 0, 1, 1], [0, 1], [0, 1], [1, 0, 1], [0, 1], [1], [0, 0, 1],
    [1, 0, 0, 1], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1], [1], [1],
    [0, 1, 1, 0, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [0, 1], [1, 1, 1], [1], [1, 0, 1],
    [0, 1, 0, 1], [0, 0, 0, 1], [1], [], [0, 0, 1], [1], [1], [0, 0, 1], [0, 0, 1, 1],
    [1, 0, 1], [1, 0, 0, 1], [], [1], [1, 0, 1, 1], [1], [1, 1, 1], [1, 0, 1, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 0, 0, 1, 0, 1], [1, 0, 1, 1],
    [0, 0, 1, 1], [1, 0, 0, 1], [1, 0, 1, 1], [], [1, 1, 1], [1, 0, 1], [1, 0, 0, 1],
    [0, 1, 0, 1], [0, 0, 0, 0, 0, 1], [1, 0, 1], [1], [1, 0, 1], [1, 0, 0, 1], [0, 1], [1],
    [0, 0, 1], [1, 0, 0, 1], [0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], [],
    [0, 0, 1, 1], [], [], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1],
    [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 0, 1, 1, 0, 1, 1, 1, 1], [1],
    [1, 0, 1], [1, 1, 1], [1, 1, 1, 1], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1], [1, 0, 1],
    [1, 1, 1], [1, 1], [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 1], [0, 1],
    [1, 0, 1], [0, 0, 0, 1, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1, 1],
    [0, 0, 0, 1], [1, 0, 1], [1, 0, 1], [0, 1], [1, 0, 1], [1, 0, 0, 1], [1, 0, 1, 1],
    [1, 0, 1], [1, 0, 1], [1], [1, 0, 0, 1], [1, 0, 1], [0, 0, 1], [1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [1, 1, 1], [1, 0, 0, 1], [],
    [0, 1, 0, 1], [0, 0, 0, 1, 1], [1, 0, 0, 1], [0, 0, 0, 1], [1, 0, 1], [1, 0, 1],
    [1, 0, 1, 1], [1, 0, 1], [1, 0, 1], [1, 1, 1, 1], [0, 0, 0, 0, 1],
    [0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1, 1, 0, 1, 1],
    [0, 0, 0, 0, 1, 1, 1, 1], [0, 1, 0, 1, 1, 0, 1, 1], [1, 0, 0, 0, 0, 0, 1, 1],
    [0, 1, 1, 1, 0, 1, 1, 1], [1, 0, 0, 1, 0, 1, 0, 1], [0, 1, 0, 1, 0, 0, 1, 1],
    [0, 1, 0, 1, 1, 1, 0, 1], [0, 0, 0, 0, 1, 0, 1, 1], [1, 1, 0, 0, 0, 0, 1, 1],
    [1, 0, 0, 1, 0, 0, 0, 1], [1, 0, 1, 1, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 1], [0, 1, 0, 1, 1, 0, 1], [1, 0, 0, 0, 0, 1, 0, 1],
    [1, 1, 1, 0, 0, 0, 1, 1], [1, 0, 1, 0, 0, 0, 1], [1, 0, 0, 1, 1, 1, 1, 1],
    [0, 1, 0, 0, 1, 0, 1, 1], [0, 1, 0, 0, 0, 1, 0, 1], [0, 1, 0, 0, 1, 1, 1, 1],
    [1, 1, 0, 0, 0, 0, 1], [1, 1], [1, 1, 1, 1, 0, 0, 1], [0, 0, 0, 1, 0, 0, 1, 1],
    [0, 1, 0, 1, 1, 0, 1], [0, 0, 0, 1, 1, 0, 0, 1], [0, 1, 0, 0, 1, 0, 1],
    [1, 1, 1, 0, 1, 1, 0, 1], [1, 0, 1, 1, 1, 1, 1, 1],
]
mem = [as_number(x) for x in mem]
pc = as_number([1, 1, 0, 0, 1])
regs = [0, 0, 0, 0]
minheaps = [[], []]
stack = []


class Imm:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return f'$0x{self.value:x}'

    def load(self):
        return self.value

    def store(self, value):
        assert False, self


class Reg:
    def __init__(self, value):
        assert value <= 3
        self.value = value

    def __str__(self):
        return f'%r{self.value}'

    def load(self):
        return regs[self.value]

    def store(self, value):
        regs[self.value] = value


class Mem:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return f'[0x{self.value:x}]'

    def load(self):
        return mem[self.value]

    def store(self, value):
        mem[self.value] = value


class IndMem:
    def __init__(self, value):
        assert value <= 3
        self.value = value

    def __str__(self):
        return f'[%r{self.value}]'

    def load(self):
        index = regs[self.value]
        if isinstance(index, int):
            return mem[index]
        else:
            var, = get_vars(index)
            result = None
            for i in reversed(range(16)):
                index_i = substitute(index, (var, z3.BitVecVal(i, 4)))
                index_i = eval(str(index_i))
                mem_val = mem[index_i]
                if isinstance(mem_val, int):
                    mem_val = z3.BitVecVal(mem_val, 16)
                elif mem_val.size() != 16:
                    mem_val = z3.ZeroExt(16 - mem_val.size(), mem_val)
                if result is None:
                    result = mem_val
                else:
                    result = ite(var == i, mem_val, result)
            return result

    def store(self, value):
        mem[regs[self.value]] = value


def parse_arg(arg):
    kind = arg & 3
    val = arg >> 2
    if kind == 0:
        return Imm(val)
    elif kind == 1:
        return Reg(val)
    elif kind == 2:
        return Mem(val)
    else:
        assert kind == 3
        return IndMem(val)


def quick_str(x):
    if isinstance(x, int):
        return f'0x{x:x}'
    else:
        return '...'


s = z3.Solver()
bad_locs = (58, 141)
minheap_counter = 1
while True:
    op = mem[pc]
    print(f'{pc}: ', end='')
    if op == 0:
        arg = parse_arg(mem[pc + 1])
        print(f'hlt {arg}')
        break
    elif op == 1:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg2.load()
        print(f'mov {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 2:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg1.load() + arg2.load()
        print(f'add {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 3:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg1.load() * arg2.load()
        print(f'mul {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 4:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg1.load() & arg2.load()
        print(f'and {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 5:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg1.load() | arg2.load()
        print(f'or {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 7:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = ite(arg1.load() == arg2.load(), 0, 1)
        print(f'setne {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 8:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = (-arg2.load()) & 0xffff
        print(f'neg {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 9:
        arg1 = parse_arg(mem[pc + 1])
        target = (pc + 2 + arg1.load()) & 0xffff
        print(f'jmp {arg1} <{target}>')
        pc = target
    elif op == 10:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        fallthrough = pc + 3
        target = fallthrough + arg1.load()
        print(f'jz {arg1} <loc_{target}>, {arg2}')
        condition = arg2.load() == 0
        if fallthrough in bad_locs:
            s.add(condition)
            pc = target
        elif target in bad_locs:
            s.add(z3.Not(condition))
            pc = fallthrough
        elif condition:
            pc = target
        else:
            pc = fallthrough
    elif op == 11:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        arg3 = parse_arg(mem[pc + 3])
        minheap = minheaps[arg1.load()]
        key = arg2.load()
        value = arg3.load()
        print(f'minheap_push {arg1}, {arg2}, {arg3}')
        minheap.append((key, value))
        pc += 4
    elif op == 12:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        arg3 = parse_arg(mem[pc + 3])
        minheap = minheaps[arg3.load()]
        print(f'minheap_pop {arg1}, {arg2}, {arg3}')
        # TODO:
        minheap_counter += 1
        arg1.store(z3.BitVecVal(minheap_counter, 16))
        arg2.store(z3.BitVecVal(minheap_counter, 16))
        pc += 4
    elif op == 13:
        arg1 = parse_arg(mem[pc + 1])
        arg2 = parse_arg(mem[pc + 2])
        result = arg2.load() & 0xffff
        print(f'mov16 {arg1}, {arg2} | {quick_str(result)}')
        arg1.store(result)
        pc += 3
    elif op == 14:
        arg = parse_arg(mem[pc + 1])
        target = arg.load()
        print(f'call {arg} <{target}>')
        stack.append(pc + 2)
        pc = target
    elif op == 15:
        target = stack.pop()
        print(f'ret <{target}>')
        pc = target
    else:
        assert False, op
assert str(s.check()) == 'sat'
print(s.model())
