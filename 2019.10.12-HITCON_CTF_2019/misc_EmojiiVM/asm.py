#!/usr/bin/env python3
import struct
code_table = {
    1: 127539,
    2: 10133,
    3: 10134,
    4: 10060,
    5: 10067,
    6: 10062,
    7: 128107,
    8: 128128,
    9: 128175,
    10: 128640,
    11: 127542,
    12: 127514,
    13: 9196,
    14: 128285,
    15: 128228,
    16: 128229,
    17: 127381,
    18: 127379,
    19: 128196,
    20: 128221,
    21: 128289,
    22: 128290,
    23: 128721,
}
data_table = {
    0: 128512,
    1: 128513,
    2: 128514,
    3: 129315,
    4: 128540,
    5: 128516,
    6: 128517,
    7: 128518,
    8: 128521,
    9: 128522,
    10: 128525,
}


# base
def add():
    return chr(code_table[0x02])


def mul():
    return chr(code_table[0x04])


def eq():
    return chr(code_table[0x09])


def jnz():
    return chr(code_table[0x0c])


def push(v):
    return chr(code_table[0x0d]) + chr(data_table[v])


def pop():
    return chr(code_table[0x0e])


def ld():
    return chr(code_table[0x0f])


def st():
    return chr(code_table[0x10])


def alloc():
    return chr(code_table[0x11])


def print_str():
    return chr(code_table[0x14])


def print_stack():
    return chr(code_table[0x15])


def print_qword():
    return chr(code_table[0x16])


def done():
    return chr(code_table[0x17])


# extended
def dup():
    return push(0) + add()


def push_int(c):
    digits = []
    while True:
        digits.append(c % 10)
        c //= 10
        if c == 0:
            break
    digits.reverse()
    code = ''
    for i, d in enumerate(digits):
        if i != 0:
            code += push(10)
            code += mul()
        code += push(d)
        if i != 0:
            code += add()
    return code


def st_bytes(gptr_index, s):
    code = ''
    for i, c in enumerate(s):
        code += push_int(c)
        code += push_int(i)
        code += push_int(gptr_index)
        code += st()
    return code


answer = open('emojivm_misc/answer.txt', 'rb').read()
answer += b'\0'

code = ''
# snippets
load_x = push(0) + push(0) + ld()
load_y = push(1) + push(0) + ld()
store_x = push(0) + push(0) + st()
store_y = push(1) + push(0) + st()
print_mul = push(1) + print_str()
print_eq = push(2) + print_str()
print_endl = push(3) + print_str()
# init
code += push(2) + alloc()  # 0: x, y
code += st_bytes(0, b'\x01\x01')
code += push(4) + alloc()  # 1
code += st_bytes(1, b' * \0')
code += push(4) + alloc()  # 2
code += st_bytes(2, b' = \0')
code += push(2) + alloc()  # 3
code += st_bytes(3, b'\n\0')
# loop
label = len(code)
code += load_y + print_qword()
code += print_mul
code += load_x + print_qword()
code += print_eq
code += load_x + load_y + mul() + print_qword()
code += print_endl
code += load_x + push(1) + add() + store_x
code += load_x + push(10) + eq()
code += push_int(label) + jnz()
code += push(1) + store_x
code += load_y + push(1) + add() + store_y
code += load_y + push(10) + eq()
code += push_int(label) + jnz()
code += done()
print(code)
