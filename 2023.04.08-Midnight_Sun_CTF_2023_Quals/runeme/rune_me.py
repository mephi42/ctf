#!/usr/bin/env python3
# coding=utf8
import sys


def rune_me(code):

    chrs = 'ᚠᚢᚦᚩᚱᚳᚷᚹ'
    size = 0x10000
    code = ''.join(c for c in code if c in chrs)

    m, dp, pc, l = [0] * size, 0, 0, []
    s = size-(len(chrs)+2)
    m[s:s+(len(chrs)-2)] = list(range(len(chrs)+1))[:8]

    while pc < len(code):

        c = code[pc]

        if c in chrs:
            op = m[s + chrs.index(c)]

            if op == 0:
                dp = (dp + 1) % size
            elif op == 1:
                dp = (dp - 1) % size
            elif op == 2:
                m[dp] = (m[dp] + 1) % 0x100
            elif op == 3:
                m[dp] = (m[dp] - 1) % 0x100
            elif op == 4:
                print(chr(m[dp]), end='', flush=True)
            elif op == 5:
                m[dp] = ord(sys.stdin.read(1))
            elif op == 6:
                if m[dp]:
                    l.append(pc)
                else:
                    open_brackets = 1
                    while open_brackets:
                        pc += 1
                        if code[pc] in chrs and m[s + chrs.index(code[pc])] == 6:
                            open_brackets += 1
                        elif code[pc] in chrs and m[s + chrs.index(code[pc])] == 7:
                            open_brackets -= 1
            elif op == 7:
                pc = l.pop() - 1

        pc += 1

    return


if __name__ == '__main__':
    r  = "ᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚦᚷᚠᚦᚠᚦᚦᚠᚦᚦᚦᚦᚦᚠᚦᚦᚦᚦᚦᚦᚠᚦᚦᚦᚦᚦᚦᚦᚢᚢᚢᚢᚢᚩᚹᚠᚠᚠᚦᚦᚦᚦᚦᚦᚱᚠᚦᚱᚦᚦᚦᚦ"
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
    rune_me(r)