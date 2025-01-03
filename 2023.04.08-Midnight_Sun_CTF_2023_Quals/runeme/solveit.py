#!/usr/bin/env python3
import os
import subprocess
import sys

CHRS = "ᚠᚢᚦᚩᚱᚳᚷᚹ"
SIZE = 0x10000
VTABLE = SIZE - (len(CHRS) + 2)
COUNTER = 0xffff


def rune_me(flag):
    m, dp, pc, l = [0] * SIZE, 0, 0, []
    m[VTABLE : VTABLE + (len(CHRS) - 2)] = list(range(len(CHRS) + 1))[:8]

    flag_i = 0
    output = ""
    delta_cov = 0

    def set_bf(op):
        if bf[pc] == "?":
            bf[pc] = op
            nonlocal delta_cov
            delta_cov += 1
        elif bf[pc] == op:
            pass
        else:
            raise Exception("wtf")

    def set_jump(dst):
        if jumps[pc] is not None and jumps[pc] != dst:
            raise Exception("wtf")
        jumps[pc] = dst

    while pc < len(code):
        c = code[pc]
        if c in CHRS:
            op = m[VTABLE + CHRS.index(c)]
            if op == 0:
                set_bf(">")
                dp = (dp + 1) % SIZE
            elif op == 1:
                set_bf("<")
                dp = (dp - 1) % SIZE
            elif op == 2:
                set_bf("+")
                m[dp] = (m[dp] + 1) % 0x100
            elif op == 3:
                set_bf("-")
                m[dp] = (m[dp] - 1) % 0x100
            elif op == 4:
                set_bf(".")
                output += chr(m[dp])
            elif op == 5:
                set_bf(",")
                if flag_i >= len(flag):
                    break
                m[dp] = flag[flag_i]
                flag_i += 1
            elif op == 6:
                set_bf("[")
                if m[dp]:
                    l.append(pc)
                else:
                    open_brackets = 1
                    dst = pc
                    while open_brackets:
                        dst += 1
                        if code[dst] in CHRS and m[VTABLE + CHRS.index(code[dst])] == 6:
                            open_brackets += 1
                        elif code[dst] in CHRS and m[VTABLE + CHRS.index(code[dst])] == 7:
                            open_brackets -= 1
                    set_jump(("[", dst + 1))
                    pc = dst
            elif op == 7:
                set_bf("]")
                dst = l.pop()
                set_jump(("]", dst))
                if dst == pc - 1:
                    # trivial infinite loop
                    break
                pc = dst - 1
        pc += 1

    return delta_cov, m, output


def linear_scan(start, end):
    delta_ptr = 0
    delta_mem = {}
    for k in range(start, end):
        if bf[k] == ">":
            delta_ptr += 1
        elif bf[k] == "<":
            delta_ptr -= 1
        elif bf[k] == "+":
            delta_mem[delta_ptr] = delta_mem.get(delta_ptr, 0) + 1
        elif bf[k] == "-":
            delta_mem[delta_ptr] = delta_mem.get(delta_ptr, 0) - 1
        else:
            return delta_ptr, delta_mem, k
    return delta_ptr, delta_mem, end


def gen_c(fp, kind):
    print("#include <stdint.h>", file=fp)
    print("#include <stdio.h>", file=fp)
    print("#include <stdlib.h>", file=fp)
    print("#include <string.h>", file=fp)
    print("#define SIZE " + str(SIZE), file=fp)
    print("#define VTABLE " + str(VTABLE), file=fp)
    print({
        "main": "int main(void) {",
        "libfuzzer": "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {"
    }[kind], file=fp)
    print("    unsigned char mem[" + str(SIZE) + "];", file=fp)
    print("    memset(mem, 0, sizeof(mem));", file=fp)
    print("    int ptr = 0;", file=fp)
    if kind == "libfuzzer":
        print("    int i = 0;", file=fp)
    for i, v in enumerate(list(range(len(CHRS) + 1))[:8]):
        print(f"    mem[VTABLE + {i}] = {v};", file=fp)
    i = 0
    while i < len(bf):
        op = bf[i]
        print(f"_{i}: /* {op} */", end="", file=fp)
        delta_ptr, delta_mem, k = linear_scan(i, len(bf))
        if k > i + 1:
            print(f"    /* {''.join(bf[i:k])} */", file=fp)
            for offset, v in delta_mem.items():
                if v != 0:
                    print(f"    mem[(ptr + {offset} + SIZE) % SIZE] += {v};", file=fp)
            if delta_ptr != 0:
                print(f"    ptr = (ptr + {delta_ptr} + SIZE) % SIZE;", file=fp)
            i = k - 1
        elif op == ">":
            print("    ptr = (ptr + 1 + SIZE) % SIZE;", file=fp)
        elif op == "<":
            print("    ptr = (ptr - 1 + SIZE) % SIZE;", file=fp)
        elif op == "+":
            print("    mem[ptr]++;", file=fp)
        elif op == "-":
            print("    mem[ptr]--;", file=fp)
        elif op == ".":
            print({
                "main": "    putchar(mem[ptr]);",
                "libfuzzer": "    if (mem[ptr] == '(') return 0;"
            }[kind], file=fp)
        elif op == ",":
            if kind == 'main':
                print("    mem[ptr] = getchar();", file=fp)
            elif kind == 'libfuzzer':
                print("    if (i >= size) return 0;", file=fp)
                print("    mem[ptr] = data[i];", file=fp)
                print("    i++;", file=fp)
            else:
                raise Exception("WTF")
        elif op == "[":
            dj = jumps[i]
            if dj is None:
                print("    if (mem[ptr] == 0) abort();", file=fp)
            else:
                assert dj[0] == "["
                j = dj[1]
                assert bf[j - 1] in "]?", (bf, i, j)

                delta_ptr, delta_mem, k = linear_scan(i + 1, j - 1)
                if delta_ptr == 0 and delta_mem.get(0) == -1 and k == j - 1:
                    print(f"    /* {''.join(bf[i:j])} */", file=fp)
                    delta_mem.pop(0)
                    for k, v in delta_mem.items():
                        if v != 0:
                            print(f"    mem[(ptr + {k} + SIZE) % SIZE] += mem[ptr] * {v};", file=fp)
                    print(f"    mem[ptr] = 0;", file=fp)
                    i = j - 1
                else:
                    print(f"    if (mem[ptr] == 0) goto _{j};", file=fp)
        elif op == "]":
            d, j = jumps[i]
            assert d == "]"
            assert bf[j] == "["
            if j == i - 1:
                print(f"    return 0; /* trivial infinite loop */", file=fp)
            else:
                print(f"    goto _{j};", file=fp)
        else:
            print("    abort();", file=fp)
        i += 1
    print("    return 0;", file=fp)
    print("}", file=fp)


def get_code():
    r = ""
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚷᚠᚦᚠᚦᚦᚠᚦᚦᚦᚦᚦᚠᚦᚦᚦᚦᚦᚦᚠᚦᚦᚦᚦᚦᚦᚦᚢᚢᚢᚢᚢᚩᚹᚠᚠᚠᚦᚦᚦᚦᚦᚦᚱᚠᚦᚱᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚱᚩᚱᚦᚦᚦᚦᚱᚩᚩᚱᚱᚩᚩᚩᚩᚩᚩᚩᚩᚱᚦᚦᚦᚦᚦᚦᚦᚦᚦᚱᚢᚢᚱᚠᚠᚠᚦᚦᚦᚦᚱᚢᚩᚩᚩᚩᚩᚱᚦᚦᚦᚱᚱᚢᚢᚱᚠᚱᚠ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚱᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚱᚩᚩᚩᚩᚩᚩᚩᚱᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚱᚱᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚱᚢᚢᚦᚱᚢ"
    r += "ᚩᚩᚩᚩᚩᚩᚱᚠᚠᚠᚠᚷᚩᚹᚢᚷᚩᚹᚢᚷᚩᚹᚢᚷᚩᚹᚢᚷᚩᚹᚢᚢᚢᚢᚢᚢᚢᚩᚩᚩᚩᚠᚩᚩᚩᚩᚠᚩᚩᚩᚩᚠᚩᚩᚩᚩᚢᚢᚢᚢᚢᚢᚢᚦᚱᚩᚱ"
    r += "ᚦᚱᚦᚢᚩᚩᚩᚩᚩᚢᚩᚩᚩᚢᚩᚩᚩᚩᚩᚢᚩᚩᚩᚢᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚢᚩᚩᚢᚩᚩᚩᚩᚩᚢᚩᚩᚩᚩᚩᚩᚢᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚢᚩᚩᚩᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚳᚢᚢᚩᚩᚳᚦᚦᚦᚳᚩᚩᚩᚩᚩᚩᚩᚳᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚳᚦᚦᚦᚦᚦᚳᚩᚳᚠᚠᚳᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚳᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚳᚠᚠᚳᚢᚢᚢᚩᚳᚠᚩᚩᚩᚩᚳᚢᚦᚦᚦᚳᚠᚦᚳᚠᚠᚳᚢᚢᚢᚩᚩᚩᚩᚩᚳᚠᚩᚩᚩᚩᚩᚩᚩᚳᚢᚦᚦᚦᚦᚳᚦᚦᚦᚳᚠᚠᚠᚳᚢᚢᚢ"
    r += "ᚩᚳᚠᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚳᚦᚦᚳᚢᚦᚳᚠᚩᚩᚳᚢᚩᚩᚳᚠᚠᚠᚳᚢᚢᚢᚦᚦᚳᚩᚩᚩᚳᚦᚦᚦᚦᚦᚦᚦᚳᚩᚩᚠᚳᚢᚩᚩᚩᚳᚢᚦᚦᚦᚦᚦᚦᚳ"
    r += "ᚠᚠᚠᚠᚳᚢᚢᚢᚢᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚷᚠᚠᚠᚠᚠᚦᚦᚦᚦᚦᚢᚦᚦᚦᚢᚦᚦᚦᚦᚦᚢᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠ"
    r += "ᚷᚷᚷᚱᚷᚷᚷᚷᚷᚱᚷᚷᚷᚱᚷᚷᚷᚷᚷᚱᚱᚱᚱᚱᚱᚱᚢᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚷᚷᚷ"
    r += "ᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳ"
    r += "ᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱ"
    r += "ᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚷᚷᚷ"
    r += "ᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦᚳᚹᚱᚹᚩᚷ"
    r += "ᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹᚳᚦᚹᚩᚩᚱ"
    r += "ᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚢᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷ"
    r += "ᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳ"
    r += "ᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱ"
    r += "ᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚱᚷᚷ"
    r += "ᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦ"
    r += "ᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹ"
    r += "ᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚢᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷ"
    r += "ᚷᚷᚷᚷᚱᚹᚩᚳᚷᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱ"
    r += "ᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦ"
    r += "ᚳᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳ"
    r += "ᚩᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱ"
    r += "ᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳ"
    r += "ᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚢᚱᚱᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷ"
    r += "ᚷᚷᚷᚷᚷᚷᚷᚷᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱ"
    r += "ᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳ"
    r += "ᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩ"
    r += "ᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷ"
    r += "ᚱᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩ"
    r += "ᚳᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚹᚹᚱᚹᚹᚹᚹᚱᚹᚹᚹᚹᚱ"
    r += "ᚹᚹᚹᚹᚱᚷᚠᚩᚠᚦᚠᚩᚢᚢᚢᚢᚢᚢᚢᚹᚹᚹᚹᚹᚳᚹᚹᚹᚳᚹᚹᚹᚹᚹᚳᚹᚹᚹᚳᚳᚳᚳᚳᚳᚳᚠᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱ"
    r += "ᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳ"
    r += "ᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩ"
    r += "ᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳ"
    r += "ᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳ"
    r += "ᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱ"
    r += "ᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚳᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹ"
    r += "ᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱ"
    r += "ᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱ"
    r += "ᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳ"
    r += "ᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹ"
    r += "ᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳ"
    r += "ᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱ"
    r += "ᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩ"
    r += "ᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳ"
    r += "ᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩ"
    r += "ᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷ"
    r += "ᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦ"
    r += "ᚱᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱ"
    r += "ᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱ"
    r += "ᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳ"
    r += "ᚳᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹ"
    r += "ᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱ"
    r += "ᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚱᚷᚷᚷᚳᚳᚷᚷᚷ"
    r += "ᚷᚷᚷᚷᚳᚷᚷᚷᚷᚷᚱᚱᚱᚦᚦᚦᚦᚠᚠᚠᚠᚠᚦᚠᚠᚠᚠᚠᚠᚠᚦᚠᚦᚠᚠᚠᚦᚦᚦᚹᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠ"
    r += "ᚦᚢᚳᚩᚠᚦᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱ"
    r += "ᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚢᚱᚱᚦᚦᚦᚦᚦᚦᚱᚦᚦᚦᚳᚠᚠᚱᚢᚩᚩᚩᚳᚩᚩᚩᚢᚳᚦᚳᚦᚦᚦᚱᚩᚳᚦᚱᚱᚦᚱᚦᚢᚩᚢᚳᚦᚱᚩᚩᚩᚩ"
    r += "ᚩᚩᚠᚦᚦᚦᚦᚦᚦᚱᚢᚳᚳᚦᚳᚠᚱᚩᚱᚩᚩᚩᚠᚠᚦᚦᚦᚢᚳᚩᚩᚳᚦᚦᚳᚩᚩᚩᚱᚩᚩᚠᚦᚦᚢᚳᚦᚦᚦᚦᚱᚦᚦᚦᚳᚩᚩᚩᚱᚢᚩᚩᚩᚳᚩᚩᚩ"
    r += "ᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚩᚱᚢᚦᚢᚩᚳᚠᚦᚱᚩᚢᚦᚱᚢᚳᚳᚩᚱᚦᚠᚩᚱᚢᚳᚳᚠᚦᚱ"
    r += "ᚩᚢᚦᚢᚳᚠᚩᚱᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦᚢᚳᚠᚱᚩᚠᚦᚢᚳᚩᚩᚩᚩᚱᚢᚳᚦᚦᚦᚱᚩᚩᚩᚠᚦᚦᚦᚢᚳᚩᚢ"
    r += "ᚩᚱᚢᚳᚳᚦᚱᚢᚳᚱᚢᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚩᚠᚦᚦᚦᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚠᚦᚦᚳᚹᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦ"
    r += "ᚢᚳᚩᚠᚠᚠᚦᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦ"
    r += "ᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚢᚱᚱᚦᚦᚦᚦᚦᚦᚱᚦᚦᚦᚳᚠᚠᚱᚢᚩᚩᚩᚳᚩᚩᚩᚢᚳᚦᚳᚦᚦᚦᚱᚩᚳᚦᚱᚱᚦᚱᚦᚢᚩᚢᚳᚦᚱᚩᚩᚩ"
    r += "ᚩᚩᚩᚠᚦᚦᚦᚦᚦᚦᚱᚢᚳᚳᚦᚳᚠᚱᚩᚱᚩᚩᚩᚠᚠᚦᚦᚦᚢᚳᚩᚩᚳᚦᚦᚳᚩᚩᚩᚱᚩᚩᚠᚦᚦᚢᚳᚦᚦᚦᚦᚱᚦᚦᚦᚳᚩᚩᚩᚱᚢᚩᚩᚩᚳᚩᚩ"
    r += "ᚩᚦᚦᚦᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚩᚱᚢᚦᚢᚩᚳᚠᚦᚱᚩᚢᚦᚱᚢᚳᚳᚩ"
    r += "ᚱᚦᚠᚩᚱᚢᚳᚳᚠᚦᚱᚩᚢᚦᚢᚳᚠᚩᚱᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦᚢᚳᚠᚱᚩᚠᚦᚢᚳᚩᚩᚩᚩᚱᚢᚳᚦᚦᚦᚱ"
    r += "ᚩᚩᚩᚠᚦᚦᚦᚢᚳᚩᚢᚩᚱᚢᚳᚳᚦᚱᚢᚳᚱᚢᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚩᚠᚦᚦᚦᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚠᚦᚦᚳᚹᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩ"
    r += "ᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚦᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚱᚦᚦᚦᚦᚠᚦ"
    r += "ᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚢᚱᚱᚦᚦᚦᚦᚦᚦᚱᚦᚦᚦᚳᚠᚠᚱᚢᚩᚩᚩᚳᚩᚩᚩᚢᚳᚦᚳᚦᚦᚦᚱᚩᚳᚦᚱ"
    r += "ᚱᚦᚱᚦᚢᚩᚢᚳᚦᚱᚩᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚦᚱᚢᚳᚳᚦᚳᚠᚱᚩᚱᚩᚩᚩᚠᚠᚦᚦᚦᚢᚳᚩᚩᚳᚦᚦᚳᚩᚩᚩᚱᚩᚩᚠᚦᚦᚢᚳᚦᚦᚦᚦᚱᚦᚦ"
    r += "ᚦᚳᚩᚩᚩᚱᚢᚩᚩᚩᚳᚩᚩᚩᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚩᚱᚢᚦᚢᚩᚳᚠᚦᚱᚩᚢᚦ"
    r += "ᚱᚢᚳᚳᚩᚱᚦᚠᚩᚱᚢᚳᚳᚠᚦᚱᚩᚢᚦᚢᚳᚠᚩᚱᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦᚢᚳᚠᚱᚩᚠᚦᚢᚳᚩᚩᚩᚩᚱᚢ"
    r += "ᚳᚦᚦᚦᚱᚩᚩᚩᚠᚦᚦᚦᚢᚳᚩᚢᚩᚱᚢᚳᚳᚦᚱᚢᚳᚱᚢᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚩᚠᚦᚦᚦᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚠᚦᚦᚳᚹᚦᚦᚠᚠᚠᚠᚠᚠᚠᚱ"
    r += "ᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚱᚦ"
    r += "ᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚢᚱᚱᚦᚦᚦᚦᚦᚦᚱᚦᚦᚦᚳᚠᚠᚱᚢᚩᚩᚩᚳᚩᚩᚩᚢᚳᚦᚳᚦᚦᚦ"
    r += "ᚱᚩᚳᚦᚱᚱᚦᚱᚦᚢᚩᚢᚳᚦᚱᚩᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚦᚱᚢᚳᚳᚦᚳᚠᚱᚩᚱᚩᚩᚩᚠᚠᚦᚦᚦᚢᚳᚩᚩᚳᚦᚦᚳᚩᚩᚩᚱᚩᚩᚠᚦᚦᚢᚳᚦᚦ"
    r += "ᚦᚦᚱᚦᚦᚦᚳᚩᚩᚩᚱᚢᚩᚩᚩᚳᚩᚩᚩᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚠᚩᚱᚢᚦ"
    r += "ᚢᚩᚳᚠᚦᚱᚩᚢᚦᚱᚢᚳᚳᚩᚱᚦᚠᚩᚱᚢᚳᚳᚠᚦᚱᚩᚢᚦᚢᚳᚠᚩᚱᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦᚢᚳᚠᚱᚩᚠ"
    r += "ᚦᚢᚳᚩᚩᚩᚩᚱᚢᚳᚦᚦᚦᚱᚩᚩᚩᚠᚦᚦᚦᚢᚳᚩᚢᚩᚱᚢᚳᚳᚦᚱᚢᚳᚱᚢᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚩᚠᚦᚦᚦᚳᚩᚱᚢᚳᚩᚱᚢᚩᚩᚠᚦᚦᚳᚩᚩ"
    r += "ᚩᚢᚢᚢᚢᚢᚩᚢᚢᚢᚩᚢᚢᚢᚢᚢᚩᚢᚢᚢᚩᚠᚠᚠᚷᚠᚠᚠᚠᚠᚷᚠᚠᚠᚷᚳᚳᚳᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚦᚹᚹᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳ"
    r += "ᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚷᚢᚹᚹᚹᚹᚳᚹ"
    r += "ᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚱᚢᚢᚹᚹᚹᚹᚹᚹᚢᚹᚹᚹᚠᚳᚳᚢᚱᚷᚷᚷᚠᚷᚷᚷᚱᚠᚹᚠᚹᚹᚹᚢᚷᚠᚹᚢ"
    r += "ᚢᚹᚢᚹᚱᚷᚱᚠᚹᚢᚷᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚹᚢᚱᚠᚠᚹᚠᚳᚢᚷᚢᚷᚷᚷᚳᚳᚹᚹᚹᚱᚠᚷᚷᚠᚹᚹᚠᚷᚷᚷᚢᚷᚷᚳᚹᚹᚱᚠᚹᚹᚹᚹᚢᚹᚹ"
    r += "ᚹᚠᚷᚷᚷᚢᚱᚷᚷᚷᚠᚷᚷᚷᚹᚹᚹᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚷᚢᚱᚹᚱᚷᚠᚳᚹ"
    r += "ᚢᚷᚱᚹᚢᚱᚠᚠᚷᚢᚹᚳᚷᚢᚱᚠᚠᚳᚹᚢᚷᚱᚹᚱᚠᚳᚷᚢᚷᚢᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚢᚷᚷᚷᚷᚳᚹᚹᚹᚹᚱᚠᚳᚢᚷᚳᚹᚱᚠᚷᚷ"
    r += "ᚷᚷᚢᚱᚠᚹᚹᚹᚢᚷᚷᚷᚳᚹᚹᚹᚱᚠᚷᚱᚷᚢᚱᚠᚠᚹᚢᚱᚠᚢᚱᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚳᚹᚹᚠᚦᚹᚳᚳᚳᚳᚳ"
    r += "ᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷ"
    r += "ᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚱᚢᚢᚹᚹᚹᚹᚹᚹᚢᚹᚹᚹᚠᚳᚳᚢᚱᚷᚷᚷᚠᚷᚷᚷᚱᚠᚹᚠᚹᚹᚹᚢᚷᚠᚹᚢᚢᚹᚢᚹᚱᚷ"
    r += "ᚱᚠᚹᚢᚷᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚹᚢᚱᚠᚠᚹᚠᚳᚢᚷᚢᚷᚷᚷᚳᚳᚹᚹᚹᚱᚠᚷᚷᚠᚹᚹᚠᚷᚷᚷᚢᚷᚷᚳᚹᚹᚱᚠᚹᚹᚹᚹᚢᚹᚹᚹᚠᚷᚷᚷᚢ"
    r += "ᚱᚷᚷᚷᚠᚷᚷᚷᚹᚹᚹᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚷᚢᚱᚹᚱᚷᚠᚳᚹᚢᚷᚱᚹᚢᚱ"
    r += "ᚠᚠᚷᚢᚹᚳᚷᚢᚱᚠᚠᚳᚹᚢᚷᚱᚹᚱᚠᚳᚷᚢᚷᚢᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚢᚷᚷᚷᚷᚳᚹᚹᚹᚹᚱᚠᚳᚢᚷᚳᚹᚱᚠᚷᚷᚷᚷᚢᚱᚠᚹ"
    r += "ᚹᚹᚢᚷᚷᚷᚳᚹᚹᚹᚱᚠᚷᚱᚷᚢᚱᚠᚠᚹᚢᚱᚠᚢᚱᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚳᚹᚹᚠᚦᚹᚹᚹᚳᚳᚢᚷᚳᚳᚳᚳᚳ"
    r += "ᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚹᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷ"
    r += "ᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚱᚢᚢᚹᚹᚹᚹᚹᚹᚢᚹᚹᚹᚠᚳᚳᚢᚱᚷᚷᚷᚠᚷᚷᚷᚱᚠᚹᚠ"
    r += "ᚹᚹᚹᚢᚷᚠᚹᚢᚢᚹᚢᚹᚱᚷᚱᚠᚹᚢᚷᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚹᚢᚱᚠᚠᚹᚠᚳᚢᚷᚢᚷᚷᚷᚳᚳᚹᚹᚹᚱᚠᚷᚷᚠᚹᚹᚠᚷᚷᚷᚢᚷᚷᚳᚹᚹᚱ"
    r += "ᚠᚹᚹᚹᚹᚢᚹᚹᚹᚠᚷᚷᚷᚢᚱᚷᚷᚷᚠᚷᚷᚷᚹᚹᚹᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳ"
    r += "ᚳᚳᚷᚢᚱᚹᚱᚷᚠᚳᚹᚢᚷᚱᚹᚢᚱᚠᚠᚷᚢᚹᚳᚷᚢᚱᚠᚠᚳᚹᚢᚷᚱᚹᚱᚠᚳᚷᚢᚷᚢᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚢᚷᚷᚷᚷᚳᚹᚹᚹᚹ"
    r += "ᚱᚠᚳᚢᚷᚳᚹᚱᚠᚷᚷᚷᚷᚢᚱᚠᚹᚹᚹᚢᚷᚷᚷᚳᚹᚹᚹᚱᚠᚷᚱᚷᚢᚱᚠᚠᚹᚢᚱᚠᚢᚱᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷ"
    r += "ᚳᚹᚹᚠᚦᚹᚹᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚹᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷ"
    r += "ᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚷᚢᚹᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚹᚢᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚱᚠᚷᚷᚷᚱᚢᚢᚹᚹᚹᚹᚹᚹᚢᚹᚹᚹᚠ"
    r += "ᚳᚳᚢᚱᚷᚷᚷᚠᚷᚷᚷᚱᚠᚹᚠᚹᚹᚹᚢᚷᚠᚹᚢᚢᚹᚢᚹᚱᚷᚱᚠᚹᚢᚷᚷᚷᚷᚷᚷᚳᚹᚹᚹᚹᚹᚹᚢᚱᚠᚠᚹᚠᚳᚢᚷᚢᚷᚷᚷᚳᚳᚹᚹᚹᚱᚠᚷ"
    r += "ᚷᚠᚹᚹᚠᚷᚷᚷᚢᚷᚷᚳᚹᚹᚱᚠᚹᚹᚹᚹᚢᚹᚹᚹᚠᚷᚷᚷᚢᚱᚷᚷᚷᚠᚷᚷᚷᚹᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚷᚢᚱᚹᚱᚷᚠᚳᚹᚢᚷ"
    r += "ᚱᚹᚢᚱᚠᚠᚷᚢᚹᚳᚷᚢᚱᚠᚠᚳᚹᚢᚷᚱᚹᚱᚠᚳᚷᚢᚷᚢᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚱᚠᚹᚹᚹᚹᚢᚷᚷᚷᚷᚳᚹᚹᚹᚹᚱᚠᚳᚢᚷᚳᚹᚱᚠᚷᚷᚷᚷ"
    r += "ᚢᚱᚠᚹᚹᚹᚢᚷᚷᚷᚳᚹᚹᚹᚱᚠᚷᚱᚷᚢᚱᚠᚠᚹᚢᚱᚠᚢᚱᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚢᚱᚠᚷᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚷᚷᚷᚷᚷᚷᚷ"
    r += "ᚷᚱᚱᚱᚱᚱᚱᚱᚹᚱᚱᚱᚱᚱᚹᚱᚱᚱᚹᚱᚠᚩᚠᚦᚠᚩᚠᚦᚢᚢᚢᚢᚢᚢᚢᚦᚦᚦᚦᚦᚦᚷᚦᚦᚦᚦᚦᚦᚷᚦᚩᚩᚷᚱᚱᚹᚱᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷ"
    r += "ᚩᚷᚷᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚷᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷ"
    r += "ᚷᚳᚢᚹᚹᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚳᚠᚠᚷᚷᚷᚷᚷᚷᚠᚷᚷᚷᚢᚱᚱᚠᚳᚹᚹᚹᚢᚹ"
    r += "ᚹᚹᚳᚢᚷᚢᚷᚷᚷᚠᚹᚢᚷᚠᚠᚷᚠᚷᚳᚹᚳᚢᚷᚠᚹᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚷᚠᚳᚢᚢᚷᚢᚱᚠᚹᚠᚹᚹᚹᚱᚱᚷᚷᚷᚳᚢᚹᚹᚢᚷᚷᚢᚹᚹᚹᚠ"
    r += "ᚹᚹᚱᚷᚷᚳᚢᚷᚷᚷᚷᚠᚷᚷᚷᚢᚹᚹᚹᚠᚳᚹᚹᚹᚢᚹᚹᚹᚷᚷᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱ"
    r += "ᚱᚱᚱᚹᚠᚳᚷᚳᚹᚢᚱᚷᚠᚹᚳᚷᚠᚳᚢᚢᚹᚠᚷᚱᚹᚠᚳᚢᚢᚱᚷᚠᚹᚳᚷᚳᚢᚱᚹᚠᚹᚠᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚠᚹᚹᚹᚹᚱᚷᚷᚷ"
    r += "ᚷᚳᚢᚱᚠᚹᚱᚷᚳᚢᚹᚹᚹᚹᚠᚳᚢᚷᚷᚷᚠᚹᚹᚹᚱᚷᚷᚷᚳᚢᚹᚳᚹᚠᚳᚢᚢᚷᚠᚳᚢᚠᚳᚢᚹᚠᚳᚢᚹᚠᚳᚹᚹᚹᚱᚷᚷᚷᚢᚹᚠᚳᚢᚹᚠᚳᚹ"
    r += "ᚹᚱᚷᚷᚢᚩᚷᚷᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱᚱᚱᚷᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹ"
    r += "ᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚳᚠᚠᚷᚷᚷᚷᚷᚷᚠᚷᚷᚷᚢᚱᚱᚠ"
    r += "ᚳᚹᚹᚹᚢᚹᚹᚹᚳᚢᚷᚢᚷᚷᚷᚠᚹᚢᚷᚠᚠᚷᚠᚷᚳᚹᚳᚢᚷᚠᚹᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚷᚠᚳᚢᚢᚷᚢᚱᚠᚹᚠᚹᚹᚹᚱᚱᚷᚷᚷᚳᚢᚹᚹᚢᚷ"
    r += "ᚷᚢᚹᚹᚹᚠᚹᚹᚱᚷᚷᚳᚢᚷᚷᚷᚷᚠᚷᚷᚷᚢᚹᚹᚹᚠᚳᚹᚹᚹᚢᚹᚹᚹᚷᚷᚷᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱ"
    r += "ᚷᚳᚢᚹᚱᚱᚹᚠᚳᚷᚳᚹᚢᚱᚷᚠᚹᚳᚷᚠᚳᚢᚢᚹᚠᚷᚱᚹᚠᚳᚢᚢᚱᚷᚠᚹᚳᚷᚳᚢᚱᚹᚠᚹᚠᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚠᚹᚹᚹᚹᚱ"
    r += "ᚷᚷᚷᚷᚳᚢᚱᚠᚹᚱᚷᚳᚢᚹᚹᚹᚹᚠᚳᚢᚷᚷᚷᚠᚹᚹᚹᚱᚷᚷᚷᚳᚢᚹᚳᚹᚠᚳᚢᚢᚷᚠᚳᚢᚠᚳᚢᚹᚠᚳᚢᚹᚠᚳᚹᚹᚹᚱᚷᚷᚷᚢᚹᚠᚳᚢᚹ"
    r += "ᚠᚳᚹᚹᚱᚷᚷᚢᚩᚷᚷᚷᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱᚱᚱᚱᚷᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹ"
    r += "ᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚳᚠ"
    r += "ᚠᚷᚷᚷᚷᚷᚷᚠᚷᚷᚷᚢᚱᚱᚠᚳᚹᚹᚹᚢᚹᚹᚹᚳᚢᚷᚢᚷᚷᚷᚠᚹᚢᚷᚠᚠᚷᚠᚷᚳᚹᚳᚢᚷᚠᚹᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚷᚠᚳᚢᚢᚷᚢᚱᚠᚹ"
    r += "ᚠᚹᚹᚹᚱᚱᚷᚷᚷᚳᚢᚹᚹᚢᚷᚷᚢᚹᚹᚹᚠᚹᚹᚱᚷᚷᚳᚢᚷᚷᚷᚷᚠᚷᚷᚷᚢᚹᚹᚹᚠᚳᚹᚹᚹᚢᚹᚹᚹᚷᚷᚷᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷ"
    r += "ᚳᚢᚹᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚹᚠᚳᚷᚳᚹᚢᚱᚷᚠᚹᚳᚷᚠᚳᚢᚢᚹᚠᚷᚱᚹᚠᚳᚢᚢᚱᚷᚠᚹᚳᚷᚳᚢᚱᚹᚠᚹᚠᚷᚷᚷᚱᚷᚱᚹ"
    r += "ᚹᚹᚹᚳᚢᚷᚷᚷᚷᚠᚹᚹᚹᚹᚱᚷᚷᚷᚷᚳᚢᚱᚠᚹᚱᚷᚳᚢᚹᚹᚹᚹᚠᚳᚢᚷᚷᚷᚠᚹᚹᚹᚱᚷᚷᚷᚳᚢᚹᚳᚹᚠᚳᚢᚢᚷᚠᚳᚢᚠᚳᚢᚹᚠᚳᚢᚹ"
    r += "ᚠᚳᚹᚹᚹᚱᚷᚷᚷᚢᚹᚠᚳᚢᚹᚠᚳᚹᚹᚱᚷᚷᚢᚩᚷᚷᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚠᚹᚱᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱᚷᚹᚹᚠᚷᚷ"
    r += "ᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚳᚢᚹᚹᚹᚹᚠᚷᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚹᚳᚢᚷᚷᚷᚷᚷᚠᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷ"
    r += "ᚳᚢᚹᚹᚹᚳᚠᚠᚷᚷᚷᚷᚷᚷᚠᚷᚷᚷᚢᚱᚱᚠᚳᚹᚹᚹᚢᚹᚹᚹᚳᚢᚷᚢᚷᚷᚷᚠᚹᚢᚷᚠᚠᚷᚠᚷᚳᚹᚳᚢᚷᚠᚹᚹᚹᚹᚹᚹᚱᚷᚷᚷᚷᚷᚷᚠᚳ"
    r += "ᚢᚢᚷᚢᚱᚠᚹᚠᚹᚹᚹᚱᚱᚷᚷᚷᚳᚢᚹᚹᚢᚷᚷᚢᚹᚹᚹᚠᚹᚹᚱᚷᚷᚳᚢᚷᚷᚷᚷᚠᚷᚷᚷᚢᚹᚹᚹᚠᚳᚹᚹᚹᚢᚹᚹᚹᚷᚷᚱᚱᚱᚱᚠᚹᚱᚱᚱ"
    r += "ᚱᚱᚱᚱᚱᚱᚱᚷᚳᚢᚹᚱᚱᚱᚹᚠᚳᚷᚳᚹᚢᚱᚷᚠᚹᚳᚷᚠᚳᚢᚢᚹᚠᚷᚱᚹᚠᚳᚢᚢᚱᚷᚠᚹᚳᚷᚳᚢᚱᚹᚠᚹᚠᚷᚷᚷᚱᚷᚱᚹᚹᚹᚹᚳᚢᚷᚷ"
    r += "ᚷᚷᚠᚹᚹᚹᚹᚱᚷᚷᚷᚷᚳᚢᚱᚠᚹᚱᚷᚳᚢᚹᚹᚹᚹᚠᚳᚢᚷᚷᚷᚠᚹᚹᚹᚱᚷᚷᚷᚳᚢᚹᚳᚹᚠᚳᚢᚢᚷᚠᚳᚢᚠᚳᚢᚹᚠᚳᚢᚹᚠᚳᚹᚹᚹᚱᚷ"
    r += "ᚷᚷᚢᚹᚠᚳᚢᚹᚠᚳᚹᚹᚱᚷᚷᚢᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚳᚳᚳᚳᚷᚳᚳᚳᚳᚳᚳᚳᚷᚳᚷᚳᚳᚳᚢᚩᚩᚩᚢᚩᚢᚩᚩᚩᚩᚩᚩᚩᚢᚩᚩᚩᚩᚩᚢᚢ"
    r += "ᚢᚱᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚩᚩᚩᚩᚩᚢᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠ"
    r += "ᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚦᚹᚹᚢᚢᚢᚢᚢᚢᚹᚢᚢᚢᚷ"
    r += "ᚩᚩᚹᚦᚠᚠᚠᚷᚠᚠᚠᚦᚷᚢᚷᚢᚢᚢᚹᚠᚷᚢᚹᚹᚢᚹᚢᚦᚠᚦᚷᚢᚹᚠᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚢᚹᚦᚷᚷᚢᚷᚩᚹᚠᚹᚠᚠᚠᚩᚩᚢᚢᚢᚦᚷᚠ"
    r += "ᚠᚷᚢᚢᚷᚠᚠᚠᚹᚠᚠᚩᚢᚢᚦᚷᚢᚢᚢᚢᚹᚢᚢᚢᚷᚠᚠᚠᚹᚦᚠᚠᚠᚷᚠᚠᚠᚢᚢᚢᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚹᚠᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚩᚩᚩᚩᚠᚹᚦᚢᚦᚠᚷᚩᚢᚹᚠᚦᚢᚹᚦᚷᚷᚠᚹᚢᚩᚠᚹᚦᚷᚷᚩᚢᚹᚠᚦᚢᚦᚷᚩᚠᚹᚠᚹᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚦ"
    r += "ᚷᚢᚢᚢᚢᚹᚠᚠᚠᚠᚩᚢᚢᚢᚢᚦᚷᚩᚹᚠᚩᚢᚦᚷᚠᚠᚠᚠᚹᚦᚷᚢᚢᚢᚹᚠᚠᚠᚩᚢᚢᚢᚦᚷᚠᚦᚠᚹᚦᚷᚷᚢᚹᚦᚷᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠ"
    r += "ᚠᚩᚢᚢᚢᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚩᚢᚢᚷᚱᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚠᚠᚹᚢᚢᚢᚢᚩ"
    r += "ᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠ"
    r += "ᚠᚠᚦᚹᚹᚢᚢᚢᚢᚢᚢᚹᚢᚢᚢᚷᚩᚩᚹᚦᚠᚠᚠᚷᚠᚠᚠᚦᚷᚢᚷᚢᚢᚢᚹᚠᚷᚢᚹᚹᚢᚹᚢᚦᚠᚦᚷᚢᚹᚠᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚢᚹᚦᚷᚷᚢ"
    r += "ᚷᚩᚹᚠᚹᚠᚠᚠᚩᚩᚢᚢᚢᚦᚷᚠᚠᚷᚢᚢᚷᚠᚠᚠᚹᚠᚠᚩᚢᚢᚦᚷᚢᚢᚢᚢᚹᚢᚢᚢᚷᚠᚠᚠᚹᚦᚠᚠᚠᚷᚠᚠᚠᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚠᚹᚦᚢᚦᚠᚷᚩᚢᚹᚠᚦᚢᚹᚦᚷᚷᚠᚹᚢᚩᚠᚹᚦᚷᚷᚩᚢᚹᚠᚦᚢᚦᚷᚩᚠ"
    r += "ᚹᚠᚹᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚹᚠᚠᚠᚠᚩᚢᚢᚢᚢᚦᚷᚩᚹᚠᚩᚢᚦᚷᚠᚠᚠᚠᚹᚦᚷᚢᚢᚢᚹᚠᚠᚠᚩᚢᚢᚢᚦᚷᚠᚦᚠᚹᚦᚷᚷᚢᚹ"
    r += "ᚦᚷᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚠᚩᚢᚢᚢᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚩᚢᚢᚷᚱᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚢᚦᚷᚠᚩᚢᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹ"
    r += "ᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚦᚹᚹᚢᚢᚢᚢᚢᚢᚹᚢᚢᚢᚷᚩᚩᚹᚦᚠᚠᚠᚷᚠᚠᚠᚦᚷᚢᚷᚢᚢᚢᚹᚠᚷᚢᚹᚹᚢᚹᚢᚦᚠᚦᚷᚢᚹᚠᚠᚠᚠ"
    r += "ᚠᚠᚩᚢᚢᚢᚢᚢᚢᚹᚦᚷᚷᚢᚷᚩᚹᚠᚹᚠᚠᚠᚩᚩᚢᚢᚢᚦᚷᚠᚠᚷᚢᚢᚷᚠᚠᚠᚹᚠᚠᚩᚢᚢᚦᚷᚢᚢᚢᚢᚹᚢᚢᚢᚷᚠᚠᚠᚹᚦᚠᚠᚠᚷᚠᚠᚠ"
    r += "ᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢᚦᚷᚠᚩᚩᚩᚩᚩᚩᚩᚩᚠᚹᚦᚢᚦᚠᚷᚩᚢᚹᚠᚦᚢᚹᚦᚷᚷᚠᚹᚢᚩᚠᚹᚦᚷᚷᚩᚢᚹᚠ"
    r += "ᚦᚢᚦᚷᚩᚠᚹᚠᚹᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚹᚠᚠᚠᚠᚩᚢᚢᚢᚢᚦᚷᚩᚹᚠᚩᚢᚦᚷᚠᚠᚠᚠᚹᚦᚷᚢᚢᚢᚹᚠᚠᚠᚩᚢᚢᚢᚦᚷᚠᚦᚠ"
    r += "ᚹᚦᚷᚷᚢᚹᚦᚷᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚠᚩᚢᚢᚢᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚩᚢᚢᚷᚱᚢᚢᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚹᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚢ"
    r += "ᚦᚷᚠᚩᚩᚩᚩᚩᚢᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚠᚹᚢᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚠᚦᚷᚢᚢᚢ"
    r += "ᚢᚢᚹᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚦᚷᚠᚠᚠᚦᚹᚹᚢᚢᚢᚢᚢᚢᚹᚢᚢᚢᚷᚩᚩᚹᚦᚠᚠᚠᚷᚠᚠᚠᚦᚷᚢᚷᚢᚢᚢᚹᚠᚷᚢᚹᚹᚢᚹᚢᚦᚠᚦᚷᚢᚹᚠ"
    r += "ᚠᚠᚠᚠᚠᚩᚢᚢᚢᚢᚢᚢᚹᚦᚷᚷᚢᚷᚩᚹᚠᚹᚠᚠᚠᚩᚩᚢᚢᚢᚦᚷᚠᚠᚷᚢᚢᚷᚠᚠᚠᚹᚠᚠᚩᚢᚢᚦᚷᚢᚢᚢᚢᚹᚢᚢᚢᚷᚠᚠᚠᚹᚦᚠᚠᚠᚷ"
    r += "ᚠᚠᚠᚢᚩᚩᚩᚩᚩᚩᚩᚩᚠᚹᚦᚢᚦᚠᚷᚩᚢᚹᚠᚦᚢᚹᚦᚷᚷᚠᚹᚢᚩᚠᚹᚦᚷᚷᚩᚢᚹᚠᚦᚢᚦᚷᚩᚠᚹᚠᚹᚢᚢᚢᚩᚢᚩᚠᚠᚠᚠᚦᚷᚢᚢᚢᚢ"
    r += "ᚹᚠᚠᚠᚠᚩᚢᚢᚢᚢᚦᚷᚩᚹᚠᚩᚢᚦᚷᚠᚠᚠᚠᚹᚦᚷᚢᚢᚢᚹᚠᚠᚠᚩᚢᚢᚢᚦᚷᚠᚦᚠᚹᚦᚷᚷᚢᚹᚦᚷᚹᚦᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚠᚩᚢᚢᚢ"
    r += "ᚷᚠᚹᚦᚷᚠᚹᚦᚠᚠᚩᚢᚢᚷᚠᚠᚠᚠᚠᚠᚦᚦᚦᚦᚦᚢᚦᚦᚦᚢᚦᚦᚦᚦᚦᚢᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚷᚷᚷᚱᚷᚷᚷᚷᚷᚱᚷᚷᚷᚱᚷᚷᚷᚷᚷᚱᚱ"
    r += "ᚱᚱᚱᚱᚱᚢᚱᚱᚱᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱ"
    r += "ᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦ"
    r += "ᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱ"
    r += "ᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷ"
    r += "ᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱ"
    r += "ᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳ"
    r += "ᚳᚷᚱᚱᚩᚢᚱᚱᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱ"
    r += "ᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳ"
    r += "ᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳ"
    r += "ᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱ"
    r += "ᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳ"
    r += "ᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚢᚱᚱᚱᚷᚷᚦ"
    r += "ᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳ"
    r += "ᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱᚦᚱᚱᚱᚩᚷᚷᚦ"
    r += "ᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱᚱᚱᚹᚩᚳᚳᚩᚱ"
    r += "ᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚷᚷ"
    r += "ᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳᚳᚷᚱᚱᚱ"
    r += "ᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹᚩᚳᚦᚹᚳ"
    r += "ᚳᚷᚱᚱᚩᚢᚱᚱᚱᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚱᚹᚩᚳᚷᚷᚷᚷᚱᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱ"
    r += "ᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚳᚦᚱᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚱᚦᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚹᚩᚳᚳᚳᚹᚦᚦᚱᚱᚱᚱᚱᚱ"
    r += "ᚦᚱᚱᚱᚩᚷᚷᚦᚹᚳᚳᚳᚩᚳᚳᚳᚹᚩᚱᚩᚱᚱᚱᚦᚳᚩᚱᚦᚦᚱᚦᚱᚹᚳᚹᚩᚱᚦᚳᚳᚳᚳᚳᚳᚷᚱᚱᚱᚱᚱᚱᚦᚹᚩᚩᚱᚩᚷᚦᚳᚦᚳᚳᚳᚷᚷᚱ"
    r += "ᚱᚱᚹᚩᚳᚳᚩᚱᚱᚩᚳᚳᚳᚦᚳᚳᚷᚱᚱᚹᚩᚱᚱᚱᚱᚦᚱᚱᚱᚩᚳᚳᚳᚦᚹᚳᚳᚳᚩᚳᚳᚳᚱᚱᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷᚦᚳᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷ"
    r += "ᚱᚹᚩᚳᚷᚷᚷᚷᚳᚦᚹᚱᚹᚳᚩᚷᚱᚦᚳᚹᚱᚦᚹᚩᚩᚳᚦᚱᚷᚳᚦᚹᚩᚩᚷᚱᚦᚳᚹᚱᚹᚩᚷᚳᚦᚳᚦᚱᚱᚱᚷᚱᚷᚳᚳᚳᚳᚹᚩᚱᚱᚱᚱᚦᚳᚳᚳ"
    r += "ᚳᚷᚱᚱᚱᚱᚹᚩᚷᚦᚳᚷᚱᚹᚩᚳᚳᚳᚳᚦᚹᚩᚱᚱᚱᚦᚳᚳᚳᚷᚱᚱᚱᚹᚩᚳᚹᚳᚦᚹᚩᚩᚱᚦᚹᚩᚦᚹᚩᚳᚦᚹᚩᚳᚦᚹᚳᚳᚳᚷᚱᚱᚱᚩᚳᚦᚹ"
    r += "ᚩᚳᚦᚹᚳᚳᚷᚱᚱᚩᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚹᚹᚱᚹᚹᚹᚹᚱᚹᚹᚹᚹᚱᚹᚹᚹᚹᚱᚷᚠᚩᚠᚦᚠᚩᚢᚢᚢᚢᚢᚢᚢᚹᚹᚹᚹᚹᚳᚹᚹᚹᚳᚹᚹᚹ"
    r += "ᚹᚹᚳᚹᚹᚹᚳᚳᚳᚳᚳᚳᚳᚠᚳᚳᚳᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳ"
    r += "ᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦ"
    r += "ᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦ"
    r += "ᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩ"
    r += "ᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹ"
    r += "ᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩ"
    r += "ᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳ"
    r += "ᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳᚳᚩ"
    r += "ᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹᚳᚳ"
    r += "ᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹ"
    r += "ᚹᚹᚹᚳᚷᚦᚱᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱ"
    r += "ᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩ"
    r += "ᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳ"
    r += "ᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩᚩᚳᚳᚳᚳᚳ"
    r += "ᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱᚩᚱᚱᚱᚹᚹ"
    r += "ᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷ"
    r += "ᚦᚱᚹᚹᚹᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱ"
    r += "ᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷ"
    r += "ᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚠᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱ"
    r += "ᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚱᚩᚳᚳᚳᚳᚹᚳᚹᚱᚱᚱᚱᚱᚷᚦᚳᚳᚳᚳᚳᚩᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚷᚦᚱᚱᚱᚷᚩ"
    r += "ᚩᚳᚳᚳᚳᚳᚳᚩᚳᚳᚳᚦᚹᚹᚩᚷᚱᚱᚱᚦᚱᚱᚱᚷᚦᚳᚦᚳᚳᚳᚩᚱᚦᚳᚩᚩᚳᚩᚳᚷᚱᚷᚦᚳᚩᚱᚱᚱᚱᚱᚱᚹᚳᚳᚳᚳᚳᚳᚩᚷᚦᚦᚳᚦᚹᚩᚱ"
    r += "ᚩᚱᚱᚱᚹᚹᚳᚳᚳᚷᚦᚱᚱᚦᚳᚳᚦᚱᚱᚱᚩᚱᚱᚹᚳᚳᚷᚦᚳᚳᚳᚳᚩᚳᚳᚳᚦᚱᚱᚱᚩᚷᚱᚱᚱᚦᚱᚱᚱᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚩ"
    r += "ᚱᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚷᚦᚱᚹᚹᚹᚹᚱᚩᚷᚳᚷᚱᚦᚹᚳᚩᚱᚷᚳᚩᚷᚦᚦᚱᚩᚳᚹᚱᚩᚷᚦᚦᚹᚳᚩᚱᚷᚳᚷᚦᚹᚱᚩᚱᚩᚳᚳᚳᚹᚳᚹᚱᚱᚱ"
    r += "ᚱᚷᚦᚳᚳᚳᚳᚩᚱᚱᚱᚱᚹᚳᚳᚳᚳᚷᚦᚹᚩᚱᚹᚳᚷᚦᚱᚱᚱᚱᚩᚷᚦᚳᚳᚳᚩᚱᚱᚱᚹᚳᚳᚳᚷᚦᚱᚷᚱᚩᚷᚦᚦᚳᚩᚷᚦᚩᚷᚦᚱᚩᚷᚦᚱᚩᚷ"
    r += "ᚱᚱᚱᚹᚳᚳᚳᚦᚱᚩᚷᚦᚱᚩᚷᚱᚱᚹᚳᚳᚦᚱᚱᚱᚱᚱᚱᚱᚱᚱᚷᚱᚷᚷᚷᚳᚳᚷᚷᚷᚷᚷᚷᚷᚳᚷᚷᚷᚷᚷᚱᚱᚱᚦᚦᚦᚦᚠᚠᚠᚠᚠᚦᚠᚠᚠᚠ"
    r += "ᚠᚠᚠᚦᚠᚦᚠᚠᚠᚦᚦᚦᚱᚢᚳᚩᚱᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚷᚷᚱᚢᚳᚦᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠ"
    r += "ᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠ"
    r += "ᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚦᚦᚦᚠ"
    r += "ᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚦᚦᚦᚠᚠᚠᚱ"
    r += "ᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠ"
    r += "ᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢ"
    r += "ᚳᚩᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠ"
    r += "ᚠᚠᚦᚢᚳᚩᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠ"
    r += "ᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠ"
    r += "ᚠᚠᚠᚦᚢᚳᚩᚠᚦᚦᚦᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚦᚦᚦᚠᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚠᚠᚠᚠᚠᚠᚠᚠᚦᚦᚦ"
    r += "ᚠᚠᚠᚠᚱᚩᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚢᚳᚩᚦᚦᚠᚠᚠᚠᚠᚠᚠᚠᚠᚠᚦᚦᚦᚦᚦᚠᚱᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦ"
    r += "ᚢᚳᚩᚱᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚦᚦᚱᚱᚦᚦᚳᚠᚱᚩᚩᚳᚦᚦᚢᚳᚠᚱᚦᚦᚳᚩᚱᚩᚱᚩᚩᚳᚦᚠᚩᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚦᚦᚱᚦᚦᚳᚩᚢᚳᚩᚱᚩᚩᚳᚦᚱᚦᚱᚦᚦᚳᚩᚠᚩᚱᚩᚩᚳᚦᚢᚳᚦᚱᚦᚦᚳᚩᚩᚱᚢᚩᚩ"
    r += "ᚳᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚩᚱᚢᚦᚢᚩᚳᚠᚦᚱᚩᚢᚦᚱ"
    r += "ᚢᚳᚳᚩᚱᚦᚠᚩᚱᚢᚳᚳᚠᚦᚱᚩᚢᚦᚢᚳᚩᚱᚩᚩᚱᚦᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚩᚢᚳᚦᚦᚦᚦᚦᚱᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚢᚳᚩᚱᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚠᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚢᚳᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚦᚦᚱᚱᚦᚦᚳᚠᚱᚩᚩᚳᚦᚦᚢᚳᚠᚱᚦᚦᚳᚩᚱᚩᚱᚩᚩᚳᚦᚠᚩᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚠᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩ"
    r += "ᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚩᚦᚦᚱᚦᚦᚳᚩᚢᚳᚩᚱᚩᚩᚳᚦᚱᚦᚱᚦᚦᚳᚩᚠᚩᚱᚩᚩᚳᚦᚢᚳᚦᚱᚦᚦᚳᚩᚩᚱᚢᚩᚩᚳᚦᚦᚦᚦᚦ"
    r += "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚷᚱᚢᚳᚩᚩᚩᚱᚦᚦᚦᚠᚦᚠᚩᚩᚩᚩᚢᚳ"
    r += "ᚦᚦᚦᚦᚱᚩᚩᚩᚩᚠᚦᚦᚦᚦᚢᚳᚠᚱᚩᚠᚦᚢᚳᚩᚩᚩᚩᚱᚢᚳᚦᚦᚦᚱᚩᚩᚩᚠᚦᚦᚦᚢᚳᚩᚱᚢᚳᚩᚠᚦᚳᚩᚢᚳᚩᚱᚢᚳᚦᚠᚱᚳᚳᚦᚩᚩᚩ"
    r += "ᚢᚢᚢᚢᚢᚩᚢᚢᚢᚩᚢᚢᚢᚢᚢᚩᚢᚢᚢᚩᚠᚠᚠᚷᚠᚠᚠᚠᚠᚷᚠᚠᚠᚷᚳᚳᚳᚳᚳᚹᚹᚹᚹᚹᚹᚹᚹᚹᚹᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚩᚩᚢᚱᚠᚷᚷᚢ"
    r += "ᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩ"
    r += "ᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷ"
    r += "ᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷ"
    r += "ᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳ"
    r += "ᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳ"
    r += "ᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳ"
    r += "ᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷ"
    r += "ᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠ"
    r += "ᚷᚹᚳᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳ"
    r += "ᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷ"
    r += "ᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳ"
    r += "ᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹ"
    r += "ᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷ"
    r += "ᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢ"
    r += "ᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷ"
    r += "ᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷ"
    r += "ᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹ"
    r += "ᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷ"
    r += "ᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠ"
    r += "ᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷ"
    r += "ᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷ"
    r += "ᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷ"
    r += "ᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠ"
    r += "ᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷ"
    r += "ᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷ"
    r += "ᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱ"
    r += "ᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹ"
    r += "ᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹ"
    r += "ᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳ"
    r += "ᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳ"
    r += "ᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹ"
    r += "ᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢ"
    r += "ᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩ"
    r += "ᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹ"
    r += "ᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹ"
    r += "ᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹ"
    r += "ᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚹᚹ"
    r += "ᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳ"
    r += "ᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷ"
    r += "ᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚹᚹᚢᚱᚷᚷᚳ"
    r += "ᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩ"
    r += "ᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱᚠᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚹ"
    r += "ᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚢᚱᚹᚹᚹᚳᚹᚳᚷᚷᚷᚷᚠᚹᚹᚹᚢᚱᚷᚷᚷᚳᚹᚹᚹᚠᚷᚹᚳᚳᚳᚳᚳᚳᚳᚳᚳᚢᚷᚳᚳᚳᚳᚳᚳᚳᚳᚳᚳᚹᚱ"
    r += "ᚠᚷᚹᚹᚢᚱᚷᚷᚳᚹᚹᚠᚷᚷᚩᚢᚱᚠᚷᚷᚷᚷᚷᚷᚷᚷᚷᚷ"
    return r


code = get_code()
bf = ["?"] * len(code)
jumps = [None] * len(code)
INPUTS = (
    b"midnight{0123456789012345678901}",
    b"JJ::",
    bytes.fromhex("f9"),
    bytes.fromhex("05b6ffff"),
    bytes.fromhex("20b0ca"),
    bytes.fromhex("ffffffffff21"),
    bytes.fromhex("04ffffffff000000"),
    bytes.fromhex("01000000a6"),
    bytes.fromhex("c32cff01ff0124242486c7"),
    bytes.fromhex("2ddbdbdbdbdbdbab"),
    bytes.fromhex("27fdff27fffffdff27ff"),
    bytes.fromhex("ff0c0c0c0c0c0c0c0c0cfff3bf"),
    bytes.fromhex("09fef56d6dff6dff6d3b6dffffca"),
    bytes.fromhex("20949427000000000001005e4b55"),
    bytes.fromhex("040404040404040401000000046c4bba40"),
    bytes.fromhex("36131336f4f4f4491304cb"),
    bytes.fromhex("94002c010000420a262600ac010008"),
    bytes.fromhex("ffffff010000c76e080000343434343466b8ff"),
    bytes.fromhex("a5a5a5a5a5a5a500000000000000000000a5ffff79"),
    bytes.fromhex("dc80016aff29f1f1f1f1f129f1f1f1b1f1"),
    bytes.fromhex("8373e7e7e760e7e7e7c82fe7e7e7eaeaeae7e787"),
    bytes.fromhex("ef0100830000fb000002000083a22d000000371e"),
    bytes.fromhex("01000000001136363636363636363626cac9c9c9c9c9c9bfa9"),
    bytes.fromhex("b45353535353535353535353535353535353535329ca29"),
    bytes.fromhex("04cb88ff9e9e4d0030494949494949494905e9e979e1e975"),
    bytes.fromhex("0000012ffc0001aeaeffffffffffffffffffffffffffffffffff887a"),
    bytes.fromhex("130101000000950000000000000000000095000000000000000000be"),
    bytes.fromhex("00000000ffffff4cff502000000000000000000000000000002006"),
    bytes.fromhex("ff2877777777777777ffffffffff00000000000000000a5bde"),
    bytes.fromhex("0000000000190000000000000000000000000000007efffffffffffffffffd0100b2"),
    bytes.fromhex("0a2d0a94746b6b6b9494949494043b2303210a77777777017794949490"),
    bytes.fromhex("e6ffffff01ff000000000000000000000000000000000000000021ffff00ff33"),
    bytes.fromhex("0a047dfa52525204d8d5deb400008989007c9a0000989ab4c6750000988ab475"),
    b"\xf9\xb6\xca:\xa6!\x00\xab\'\x86\xcb\xf3K\xca\x08\xb1@\xb87\x87y\xca\xc9u\xde \x88\xbe\x90\x8a\xfd3",
)


def main_fuzz():
    os.makedirs("out", exist_ok=True)
    for i, flag in enumerate(INPUTS):
        print(f"run #{i}", file=sys.stderr)
        delta_cov, _, _ = rune_me(flag)
        print(delta_cov, file=sys.stderr)
        assert delta_cov > 0
        with open(f"out/{i}", "wb") as fp:
            fp.write(flag)
    while True:
        bf_str = "".join(bf)
        print(bf_str)
        bf_frag = '><<[>>>>+>+<<<<<-]>>>>>[<<<<<+>>>>>-]<<<<[>>>>+>+<<<<<-]>>>>>[<<<<<+>>>>>-]<<<-[[>>>>>>[>>>]++[-<<<]<<<-]>]>>>[<]>[[>[>-<-]>[<<<<<<+>>>>>>[-]]>]+[<[<<<++>>>-]<<]>>]<<<[<<+>>-]>>>>[>>>]<<<[-<<<]<<<>'
        i = -1
        while True:
            i = bf_str.find(bf_frag, i + 1)
            if i == -1:
                break
            print(f"{i}-{i + len(bf_frag)}")
        with open("main.c", "w") as fp:
            gen_c(fp, kind='main')
        subprocess.check_call(
            ["gcc", "-O0", "-g", "-Wall", "-Wno-unused-label", "main.c", "-o", "main"]
        )
        with open("1.c", "w") as fp:
            gen_c(fp, kind='libfuzzer')
        subprocess.check_call(
            ["clang", "-fsanitize=fuzzer", "-O3", "-g", "-Wall", "-Wno-unused-label", "1.c"]
        )
        subprocess.call(["./a.out", "-exact_artifact_path=crash", "out"])
        with open("crash", "rb") as fp:
            inp = fp.read()
        delta_cov, _, _ = rune_me(inp)
        print(delta_cov, file=sys.stderr)
        assert delta_cov > 0
        with open("inps", "a") as fp:
            print("bytes.fromhex(\"" + inp.hex() + "\"),", file=fp)


def main_brute():
    flag = bytearray(b'midnight{0123456789012345678901}')
    known = b''
    known = b"\xf9\xb6\xca:\xa6!\x00\xab\'\x86\xcb\xf3K\xca\x08\xb1@\xb87\x87y\xca\xc9u\xde \x88\xbe\x90\x8a\xfd3"
    flag[0:len(known)] = known
    for i in range(len(known), len(flag)):
        for b in reversed(range(256)):
            flag[i] = b
            _, mem, _ = rune_me(flag)
            print((flag, mem[COUNTER]))
            if mem[COUNTER] == 31 - i:
                break
    _, mem, output = rune_me(flag)
    assert mem[COUNTER] == 0
    print(output)


def main():
    main_brute()
    # midnight{c0d1n_l1KE_0d1N_br4iNf_cK_m45t3r}


if __name__ == "__main__":
    main()
