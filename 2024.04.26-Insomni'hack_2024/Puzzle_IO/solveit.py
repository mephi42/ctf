#!/usr/bin/env python3
def rev(x):
    return int(''.join(reversed(bin(x)[2:])), 2)
# lsb
flag = """\
00101000
01001000
00010100
00011010
10000100
00101000
00011110
11001101
01010011
00110110
11110101
01010001
11110110
01010101
11111101
11110010
00111110
01010101
11110100
00000010
11111011
00110110
01000000
11100010
00110010
00110010
00110110
00100010
10011010
00101000
11111001
11000000
"""
flag = flag.split()
#flag = bytearray(int(''.join(reversed(x)), 2) for x in flag)
flag = bytearray(int(x, 2) for x in flag)
sauce = [0x9e, 0xb6, 0xc1, 0x61, 0x56, 0x85, 0xcc, 0xbd]
for i, b in enumerate(flag):
    sauce_b = sauce[i & 7]
    if i & 3 == 0:
        flag[i] = flag[i] ^ (sauce_b ^ 0xff)
    elif i & 3 == 1:
        flag[i] = flag[i] ^ (sauce_b & 0xf)
    elif i & 3 == 2:
        flag[i] = (flag[i] - sauce_b) & 0xff
    else:
        flag[i] = flag[i] ^ sauce_b
print(flag)  # INS{--Rp2040_P1O_S3cR3t_S4uC3--}
