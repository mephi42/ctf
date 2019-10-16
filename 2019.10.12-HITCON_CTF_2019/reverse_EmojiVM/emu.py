#!/usr/bin/env python3
import sys
import z3

bytecode = open(sys.argv[1], 'rb').read().decode()
answer = [z3.BitVec(f'flag[{i}]', 8) for i in range(24)]
solver = z3.Solver()
for c in answer:
    solver.add(c != 0x00)
    solver.add(c != 0x0A)
answer[0] = ord(b'p')
answer[1] = ord(b'l')
answer[2] = ord(b'i')
answer[3] = ord(b's')
answer[5] = ord(b'g')
answer[6] = ord(b'1')
answer[7] = ord(b'v')
answer[8] = ord(b'3')
answer[10] = ord(b'm')
answer[11] = ord(b'e')
answer[12] = ord(b'3')
answer[13] = ord(b'3')
answer[14] = ord(b't')
answer[15] = ord(b't')
answer[16] = ord(b'h')
answer[17] = ord(b'3')
answer[18] = ord(b'e')
answer[20] = ord(b'f')
answer[21] = ord(b'1')
answer[22] = ord(b'4')
answer[23] = ord(b'g')
for i in (0x4, 0x9, 0xE, 0x13):
    answer[i] = ord(b'-')
print(bytes(answer).decode())


def eq(a, b):
    if type(a) is int:
        cond = b == a
    else:
        cond = a == b
    if type(cond) is bool:
        return 1 if cond else 0
    else:
        return z3.If(cond, 1, 0)


def check(x):
    if type(x) == bool:
        return 'sat' if x else 'unsat'
    return solver.check(x)


def model(result):
    values = {}
    if isinstance(result, str):
        return values
    m = solver.model()
    for c in answer:
        if isinstance(c, int):
            continue
        values[c] = chr(m[c].as_long())
    return values


predefined_inputs = [
    answer,
]
code_table = {
    127539: 1,
    10133: 2,
    10134: 3,
    10060: 4,
    10067: 5,
    10062: 6,
    128107: 7,
    128128: 8,
    128175: 9,
    128640: 10,
    127542: 11,
    127514: 12,
    9196: 13,
    128285: 14,
    128228: 15,
    128229: 16,
    127381: 17,
    127379: 18,
    128196: 19,
    128221: 20,
    128289: 21,
    128290: 22,
    128721: 23,
}
data_table = {
    128512: 0,
    128513: 1,
    128514: 2,
    129315: 3,
    128540: 4,
    128516: 5,
    128517: 6,
    128518: 7,
    128521: 8,
    128522: 9,
    128525: 10,
}
pc = 0
stack = [None] * 10 + [0, 0]
gptr = stack
while True:
    code = code_table[ord(bytecode[pc])]
    if code == 1:
        print(f'0x{pc:05X} NOP')
        pc += 1
    elif code == 2:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} ADD {arg0} {arg1}')
        stack.append(arg0 + arg1)
        pc += 1
    elif code == 3:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} SUB {arg0} {arg1}')
        stack.append(arg0 - arg1)
        pc += 1
    elif code == 4:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} MUL {arg0} {arg1}')
        stack.append(arg0 * arg1)
        pc += 1
    elif code == 5:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} MOD {arg0} {arg1}')
        stack.append(arg0 % arg1)
        pc += 1
    elif code == 6:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} XOR {arg0} {arg1}')
        stack.append(arg0 ^ arg1)
        pc += 1
    elif code == 7:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} AND {arg0} {arg1}')
        stack.append(arg0 & arg1)
        pc += 1
    elif code == 8:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} LT {arg0} {arg1}')
        stack.append(1 if arg0 < arg1 else 0)
        pc += 1
    elif code == 9:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} EQ {arg0} {arg1}')
        stack.append(eq(arg0, arg1))
        pc += 1
    elif code == 0xa:
        # btw this and all of the above do not check for underflow - pwn opportunity?
        pc = stack.pop()
        print(f'0x{pc:05X} JMP {pc}')
    elif code == 0xb:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} JNZ {arg0} {arg1}')
        can_be_0 = check(arg1 == 0)
        if str(can_be_0) == 'unsat':
            pc = arg0
        else:
            m0 = model(can_be_0)
            cannot_be_0 = check(arg1 != 0)
            if str(cannot_be_0) == 'unsat':
                pc += 1
            else:
                m1 = model(cannot_be_0)
                print(m0)
                print(m1)
                raise Exception('Too dumb to fork')
    elif code == 0xc:
        arg0 = stack.pop()
        arg1 = stack.pop()
        print(f'0x{pc:05X} JZ {arg0} {arg1}')
        if arg1 == 0:
            pc = arg0
        else:
            pc += 1
    elif code == 0xd:
        if len(stack) == 1024:
            raise Exception('Stack overflow')
        value = data_table[ord(bytecode[pc + 1])]
        print(f'0x{pc:05X} PUSH {value}')
        stack.append(value)
        pc += 2
    elif code == 0xe:
        if len(stack) == 0:
            raise Exception('Stack underflow')
        arg0 = stack.pop()
        print(f'0x{pc:05X} POP {arg0}')
        pc += 1
    elif code == 0xf:
        index = stack.pop()
        offset = stack.pop()
        print(f'0x{pc:05X} LD {index}[{offset}]')
        stack.append(gptr[index][offset])
        pc += 1
    elif code == 0x10:
        index = stack.pop()
        offset = stack.pop()
        value = stack.pop() & 0xff
        print(f'0x{pc:05X} ST {index}[{offset}] <- {value}')
        gptr[index][offset] = value
        pc += 1
    elif code == 0x11:
        size = stack.pop()
        if size > 1500:
            raise Exception('Size is too large')
        print(f'0x{pc:05X} NEW 0x{size:X}')
        for i in range(len(gptr)):
            if gptr[i] is None:
                gptr[i] = [0] * size
                print(f'        INDEX = 0x{i:x}')
                break
        pc += 1
    elif code == 0x12:
        index = stack.pop()
        print(f'0x{pc:05X} DEL {index}')
        if gptr[index] is None:
            raise Exception('Not allocated')
        gptr[index] = None
        pc += 1
    elif code == 0x13:
        index = stack.pop()
        print(f'0x{pc:05X} INPUT {index}')
        if gptr[index] is None:
            raise Exception('Not allocated')
        # btw we can omit trailing \0 - read opportunity?
        gptr_element = gptr[index]
        if len(predefined_inputs) == 0:
            raw = input().encode()
        else:
            raw = predefined_inputs.pop(0)
        print(f'        PREDEFINED {raw}')
        gptr_element[:len(raw)] = raw
        pc += 1
    elif code == 0x14:
        index = stack.pop()
        print(f'0x{pc:05X} PRINT GPTR ASCIIZ {index}')
        if gptr[index] is None:
            raise Exception('Not allocated')
        gptr_element = gptr[index]
        gptr_element_len = gptr_element.index(0)
        if gptr_element_len == -1:
            raise Exception('No trailing zero')  # this is NOT a part of VM
        print(bytes(gptr_element[:gptr_element_len]).decode(), end='')
        pc += 1
    elif code == 0x15:
        print(f'0x{pc:05X} PRINT STACK ASCIIZ')
        raise Exception('TODO')
    elif code == 0x16:
        value = stack.pop()
        print(f'0x{pc:05X} PRINT {value}')
        pc += 1
    elif code == 0x17:
        print(f'0x{pc:05X} RETURN')
        break
    else:
        raise Exception(f'Not implemented: 0x{code:X}')
