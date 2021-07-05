import struct
import subprocess

import numpy
import numpy.linalg
from sage.all import *


numpy.set_printoptions(linewidth=numpy.inf)


def decode_bfloat_qq(i, e_bits, f_bits):
    s = (i >> (e_bits + f_bits)) & 1
    e = ((i >> f_bits) & ((1 << e_bits) - 1)) - 127
    f = i & ((1 << f_bits) - 1)
    x = f
    # https://www.h-schmidt.net/FloatConverter/IEEE754.html
    # If the exponent has minimum value (all zero), special rules for
    # denormalized values are followed. The exponent value is set to 2**-126
    # and the "invisible" leading bit for the mantissa is no longer used.
    if e == -127:
        e = -126
    else:
        x += 1 << f_bits
    y = 1 << f_bits
    if e > 0:
        x *= 2 ** e
    else:
        y *= 2 ** (-e)
    if s == 1:
        x = -x
    return x, y


def decode_bfloat16_qq(i):
    return decode_bfloat_qq(i, 8, 7)


def decode_bfloat16(i):
    x, y = decode_bfloat16_qq(i)
    return x / y


# 6543210
# 1/2
#  1/4
#   1/8
#    1/16
#     1/32
#      1/64
#       1/128

# #include <stdio.h>
# int main() {
# 	union {
# 		unsigned int i;
# 		float f;
# 	} u;
# 	u.f = 5472;
# 	printf("%032x\n", u.i);
# }
# 00000000000000000000000045ab0000

# >>> hex(5472)
# '0x1560'
assert decode_bfloat16(0x45AB) == 5472.0
assert decode_bfloat16(0x3E00) == 0.125
assert decode_bfloat16(0xBE00) == -0.125
assert decode_bfloat16(0) == 0
assert decode_bfloat16(0x42D3) == 105.5
assert decode_bfloat16(0x42D4) == 106


def decode_bfloat32_qq(i):
    return decode_bfloat_qq(i, 8, 23)


def decode_bfloat32(i):
    x, y = decode_bfloat32_qq(i)
    return x / y


assert decode_bfloat32(0x45AB0000) == 5472.0


def encode_bfloat(f, e_bits, f_bits):
    if f == 0.0:
        return 0x0
    if f < 0:
        s = 1
        f = -f
    else:
        s = 0
    e = 0
    while f < 1:
        e -= 1
        f *= 2
    while f >= 2:
        e += 1
        f /= 2
    f = int(round((f - 1) * (1 << f_bits)))
    if f == (1 << f_bits):
        e += 1
        f = 0
    assert 0 <= s < 1
    assert 0 <= f < (1 << f_bits)
    assert -127 <= e < 128
    return (s << (e_bits + f_bits)) | ((e + 127) << f_bits) | f


def encode_bfloat16(f):
    return encode_bfloat(f, 8, 7)


assert encode_bfloat16(5472.0) == 0x45AB
assert decode_bfloat16(encode_bfloat16(41 / 4)) == 41 / 4
assert encode_bfloat16(7.99097025) == 0x4100
assert decode_bfloat16(0x40FF) == 7.96875
assert encode_bfloat16(105.99774256) == 0x42D4
assert decode_bfloat32(0x4600CFE6) == 8243.974609375
assert decode_bfloat32(0x46013D0A) == 8271.259765625
assert decode_bfloat32(0x46013DE6) == 8271.474609375


def encode_bfloat32(f):
    return encode_bfloat(f, 8, 23)


assert encode_bfloat32(5472.0) == 0x45AB0000


exp_dump = """0x7ffeda522f90:	0x45ab5dcc	0x46013e4c	0x45c2b6cc	0x45ca494c
0x7ffeda522fa0:	0x45f9da98	0x460b6dcc	0x45dec0cc	0x460692e6
0x7ffeda522fb0:	0x45ae350c	0x4603616e	0x45c5eaac	0x45cd9eac
0x7ffeda522fc0:	0x45fe023c	0x460dbe5e	0x45e2644c	0x4608ccc6
0x7ffeda522fd0:	0x45b0e94c	0x46056a12	0x45c8f68c	0x45d0ca8c
0x7ffeda522fe0:	0x4600fb72	0x460ff272	0x45e5d9cc	0x460aeb26
0x7ffeda522ff0:	0x45b4054c	0x4607c126	0x45cc794c	0x45d4718c
0x7ffeda523000:	0x46034126	0x46127ac6	0x45e9d84c	0x460d5b26
0x7ffeda523010:	0x45b695cc	0x4609ae56	0x45cf5c4c	0x45d772cc
0x7ffeda523020:	0x46052116	0x46149156	0x45ed1ecc	0x460f5d66
0x7ffeda523030:	0x45b9a9cc	0x460c0046	0x45d2d6cc	0x45db114c
0x7ffeda523040:	0x46076146	0x461713c6	0x45f114cc	0x4611c6e6
0x7ffeda523050:	0x45bc80cc	0x460e235e	0x45d60a8c	0x45de668c
0x7ffeda523060:	0x460974fe	0x4619643e	0x45f4b84c	0x461400a6
0x7ffeda523070:	0x45bf354c	0x46102c06	0x45d9168c	0x45e1928c
0x7ffeda523080:	0x460b6f66	0x461b9866	0x45f82dcc	0x46161f26"""
exp = matrix(
    QQ,
    8,
    8,
    [
        QQ(decode_bfloat32_qq(int(exp_str, 16)))
        for exp_line in exp_dump.split("\n")
        for exp_str in exp_line.split()[1:]
    ],
)
print("=== QQ expected result ===")
print(exp)

src_dump = """     [0]  3fe63dcc 40a64060 410940dc 41404124 4176415b 41964188 41b141a4 41cc41bf
     [1]  40063ecc 40b04073 410e40e6 41444129 417b4160 4198418b 41b441a6 41cf41c1
     [2]  40193f33 40b94083 411340f0 4149412e 41804164 419b418d 41b641a8 41d141c4
     [3]  402c3f80 40c3408c 411840f9 414e4133 41824169 419d4190 41b841ab 41d441c6
     [4]  40403fa6 40cc4096 411c4101 41534138 4184416e 41a04192 41bb41ad 41d641c8
     [5]  40533fcc 40d640a0 41214106 4158413c 41874173 41a24194 41bd41b0 41d841cb
     [6]  40663ff3 40e040a9 4126410b 415c4141 41894178 41a44197 41c041b2 41db41cd
     [7]  4079400c 40e940b3 412b4110 41614146 418c417c 41a74199 41c241b4 41dd41d0"""
src = matrix(
    QQ,
    8,
    8,
    [
        [
            QQ(decode_bfloat16_qq(int(src_str[4:], 16)))
            for src_str in src_line.split()[1:]
        ]
        for src_line in src_dump.split("\n")
    ],
)
print("=== QQ constant ===")
print(src)
print("=== QQ solution ===")
solution = src.solve_right(exp)  # src * solution == exp
solution = numpy.rint(solution)
print(solution)
print("=== Constant ===")
print(numpy.array(src))
print("=== Solution ===")
print(numpy.array(solution))
print("=== Result ===")
result = numpy.dot(src, solution)
print(result)
print("=== Result error ===")
print(result - exp)
print("=== bfloat16 constant ===")
src_bfloat16 = numpy.array(
    [[decode_bfloat16(encode_bfloat16(src[i][j])) for j in range(8)] for i in range(8)]
)
print(src_bfloat16)
print("=== bfloat16 solution ===")
solution_bfloat16 = numpy.array(
    [
        [decode_bfloat16(encode_bfloat16(solution[i][j])) for j in range(8)]
        for i in range(8)
    ]
)
print(solution_bfloat16)
print("=== bfloat16 solution error ===")
print((solution_bfloat16 - numpy.array(solution)))
print("=== bfloat16 constant error ===")
print((src_bfloat16 - numpy.array(src)))
print("=== bfloat16 result ===")
res_bfloat16 = numpy.dot(src_bfloat16, solution_bfloat16)
print(res_bfloat16)
print("=== bfloat16 encoded result ===")
res_bfloat16_bin = [
    struct.pack(">I", encode_bfloat32(res_bfloat16[i][j])).hex()
    for i in range(8)
    for j in range(8)
]
print(res_bfloat16_bin)
print("=== bfloat16 result error ===")
print((res_bfloat16 - numpy.array(exp)))
print("=== bfloat16 encoded solution ===")
solution_bfloat16_bin = b"".join(
    [
        struct.pack("<HH", encode_bfloat16(solution[i][j]), 0)
        for i in range(8)
        for j in range(8)
    ]
)
# => 0x402299:	tileloadd (%r14,%r12,1),%tmm4
# (gdb) p/x $r12
# $4 = 0x20
print("b *0x402299")
print(
    'python gdb.selected_inferior().write_memory(gdb.parse_and_eval("$r14"), bytes.fromhex("'
    + solution_bfloat16_bin.hex()
    + '"))'
)

# written by 0x402a1d
exp2_dump = """0x7ffd2b5f94b0:	0x0000792d	0x000057e4	0x00005557	0x00004d46
0x7ffd2b5f94c0:	0x0000213f	0x000042e7	0x000035ce	0x00004387
0x7ffd2b5f94d0:	0x00007270	0x00005084	0x00005b24	0x0000466c
0x7ffd2b5f94e0:	0x00002729	0x00003472	0x00003a6e	0x00004c62
0x7ffd2b5f94f0:	0x0000581b	0x000044a2	0x0000426e	0x00003d9a
0x7ffd2b5f9500:	0x00001493	0x00003632	0x00003032	0x00002f30
0x7ffd2b5f9510:	0x00007684	0x00004b5a	0x00004731	0x00004361
0x7ffd2b5f9520:	0x0000206a	0x00003f34	0x00003953	0x00004814
0x7ffd2b5f9530:	0x00006d16	0x00003ffe	0x00004b08	0x000040c7
0x7ffd2b5f9540:	0x00001f09	0x0000334b	0x00003af5	0x000047a0
0x7ffd2b5f9550:	0x0000683b	0x0000549e	0x0000504d	0x0000453b
0x7ffd2b5f9560:	0x00001ea6	0x00003c19	0x000035aa	0x00003c18
0x7ffd2b5f9570:	0x000068e6	0x00004abd	0x00004ded	0x00004169
0x7ffd2b5f9580:	0x00001c3a	0x0000374a	0x0000359f	0x00004102
0x7ffd2b5f9590:	0x00006e85	0x00004e31	0x00004924	0x00003f49
0x7ffd2b5f95a0:	0x0000219d	0x0000394a	0x0000308a	0x000044c8"""
exp2 = matrix(
    Integers(2 ** 32),
    8,
    8,
    [
        int(exp2_str, 16)
        for exp2_line in exp2_dump.split("\n")
        for exp2_str in exp2_line.split()[1:]
    ],
)
print("=== Expected result #2 ===")
print(exp2)
# INS 0x00000000004029f7             AMX_TILE tilezero tmm5
# INS 0x00000000004029fc             AMX_INT8 tdpbuud tmm5, tmm6, tmm7
# INS 0x0000000000402a01             AMX_TILE tilestored ptr [rbp+rbx*1], tmm5
src2_dump = """     [0]   8915782 59728d81 484e4839 8d574e48 4b0b117d 1f08948d 447e2c81 8c1b8269
     [1]  932d898d 3f213246 427a008d 7a89936f 89478b1f 24302a1e  d5d890b 235c7c31
     [2]  12432392 953b242c 53208b00 113b0436 311b3e19 69226079 91797525 331e432e
     [3]  5e4f823a 3773536a 706f885c 8255240d 43194f92 2c1e6a63 46032549 50963380
     [4]  8362327f 9310000d 31938340 6e43093a 772b7c93  f69002f 2b1b8b0b 4b3f4a7e
     [5]  7c965844 7c537118 377e2354 6e248f4d  1070288 7977143d 6890491d 2a0d4551
     [6]  92312d3a 4a42471f 716b3228 6746441b 3e13806b 8593431a 1b730b96 25665539
     [7]  13880f2e 825e550d 6f651385 6c637748 924e1e25 7a26713c 186d3601 64289581"""
# Each solution DWORD consists of a hex nibble replicated 4 times.
# INS 0x0000000000402981             BASE     mov byte ptr [rax], dl
# Write *(UINT8*)0x00007ffd5836b560 = 0xf
# INS 0x0000000000402983             BASE     add rax, 0x4                             | rax = 0x7ffd5836b564, rflags = 0x202
# INS 0x0000000000402987             BASE     mov byte ptr [rax-0x3], dl
# Write *(UINT8*)0x00007ffd5836b561 = 0xf
# INS 0x000000000040298a             BASE     mov byte ptr [rax-0x2], dl
# Write *(UINT8*)0x00007ffd5836b562 = 0xf
# INS 0x000000000040298d             BASE     mov byte ptr [rax-0x1], dl
# Write *(UINT8*)0x00007ffd5836b563 = 0xf
# So again we have matrix multiplication: nibble * (src[0] + src[1] + src[2] + src[3])
def sum_bytes(i):
    return (i & 0xFF) + ((i >> 8) & 0xFF) + ((i >> 16) & 0xFF) + ((i >> 24) & 0xFF)
def replicate_hex_nibble(i):
    assert 0 <= i <= 0xf
    return i | (i << 8) | (i << 16) | (i << 24)

src2 = matrix(
    Integers(2 ** 32),
    8,
    8,
    [
        [sum_bytes(int(src2_str, 16)) for src2_str in src2_line.split()[1:]]
        for src2_line in src2_dump.split("\n")
    ],
)
print("=== Constant #2 ===")
print(src2)
print("=== Solution #2 ===")
solution2 = src2.solve_right(exp2)
print(solution2)
solution2_bin = b"".join(
    [struct.pack("<I", replicate_hex_nibble(int(solution2[i, j]))) for i in range(8) for j in range(8)]
)
print("=== Result #2 ===")
print(src2 * solution2)
# INS 0x00000000004029cd             AMX_TILE tileloadd tmm7, ptr [rbp+rbx*1]
print("b *0x4029cd")
print(
    'python gdb.selected_inferior().write_memory(gdb.parse_and_eval("$rbp"), bytes.fromhex("'
    + solution2_bin.hex()
    + '"))'
)
h = "0123456789abcdef"
flag = "flag{"
# INS 0x0000000000401e64             AMX_TILE tileloadd tmm1, ptr [r14+rbp*1]   # tmm1 = [1        0        0        0        0        0        0        0]
# INS 0x0000000000401e7c             AMX_INT8 tdpbuud tmm3, tmm1, tmm2          # tmm3 = tmm1 * tmm2
# INS 0x0000000000401e89             AMX_TILE tilestored ptr [rsi+rbp*1], tmm3  # row0 = tmm3
# INS 0x0000000000401f09             AMX_INT8 tdpbuud tmm1, tmm3, tmm2          # tmm1 = tmm1 + tmm3 * tmm2
# INS 0x0000000000401f13             AMX_TILE tilestored ptr [rsi+rax*1], tmm1  # row1 = tmm1
# INS 0x0000000000401f92             AMX_INT8 tdpbuud tmm3, tmm1, tmm2          # tmm3 = tmm3 + tmm1 * tmm2
# INS 0x0000000000401f9c             AMX_TILE tilestored ptr [rsi+rax*1], tmm3  # row2 = tmm3
# INS 0x0000000000402022             AMX_INT8 tdpbuud tmm1, tmm3, tmm2          # tmm1 = tmm1 + tmm3 * tmm2
# INS 0x000000000040202c             AMX_TILE tilestored ptr [rsi+rax*1], tmm1  # row3 = tmm1
# INS 0x00000000004020b2             AMX_INT8 tdpbuud tmm3, tmm1, tmm2          # tmm3 = tmm3 + tmm1 * tmm2
# INS 0x00000000004020bc             AMX_TILE tilestored ptr [rsi+rax*1], tmm3  # row4 = row5 = row6 = row7 = tmm3

# row0 = iv * flag
# row1 = iv + row0 * flag
# row2 = row0 + row1 * flag
# row3 = row1 + row2 * flag
# row4 = row2 + row3 * flag

# thx @hellman + z3
flag8_str = """0 1 0 0 1 1 0 0
0 0 0 0 0 0 0 1
1 0 0 1 1 0 1 0
1 1 0 0 0 0 1 1
1 0 1 0 1 1 0 0
0 1 0 1 1 1 0 1
0 0 1 0 0 0 1 0
0 1 1 1 0 1 1 1"""
flag += "".join([
    "{:02x}".format(int("".join(reversed(flag8_line.replace(" ", ""))), 2))
    for flag8_line in flag8_str.split("\n")
])

# from z3 import *
#
# s = Solver()
# tmm2 = [[Int("x%d_%d" % (x, y)) for x in range(8)] for y in range(8)]
#
# for row in tmm2:
#     for x in row:
#         s.add(0 <= x)
#         s.add(x <= 1)
#
# def mul(a, b): return [a * b for a, b in zip(a, b)]
# def add(a, b): return [a + b for a, b in zip(a, b)]
#
# def vec_x_mat(vec, mat):
#     res = [0] * 8
#     for y in range(8):
#         for x in range(8):
#             res[x] += vec[y] * mat[y][x]
#     return res
#
# rows = [
# [  0,   1,   0,   0,   1,   1,   0,   0],
# [  2,   1,   1,   1,   2,   2,   0,   2],
# [  4,   8,   4,   5,   8,   9,   4,   6],
# [ 19,  25,  19,  20,  27,  29,  19,  30],
# [ 70, 106,  80,  83, 102, 114,  92, 110],
# [ 70, 106,  80,  83, 102, 114,  92, 110],
# [ 70, 106,  80,  83, 102, 114,  92, 110],
# [ 70, 106,  80,  83, 102, 114,  92, 110],
# ]
#
# # tmm1 = [1        0        0        0        0        0        0        0]
# tmm1 = [1] + [0] * 7
# # tmm3 = tmm1 * tmm2
# # row0 = tmm3
# row0 = tmm3 = vec_x_mat(tmm1, tmm2)
# # tmm1 = tmm1 + tmm3 * tmm2
# # row1 = tmm1
# row1 = tmm1 = add(tmm1, vec_x_mat(tmm3, tmm2))
# # tmm3 = tmm3 + tmm1 * tmm2
# # row2 = tmm3
# row2 = tmm3 = add(tmm3, vec_x_mat(tmm1, tmm2))
# # tmm1 = tmm1 + tmm3 * tmm2
# # row3 = tmm1
# row3 = tmm1 = add(tmm1, vec_x_mat(tmm3, tmm2))
# # tmm3 = tmm3 + tmm1 * tmm2
# # row4 = row5 = row6 = row7 = tmm3
# row4 = tmm3 = add(tmm3, vec_x_mat(tmm1, tmm2))
#
# def eqvec(a, b):
#     for va, vb in zip(a, b):
#         s.add(va == vb)
#
# eqvec(row0, rows[0])
# eqvec(row1, rows[1])
# eqvec(row2, rows[2])
# eqvec(row3, rows[3])
# eqvec(row4, rows[4])
#
# print(s.check())
# model = s.model()
#
# for row in tmm2:
#     print(*[model[v] for v in row])

for i in range(8):
    for j in range(8):
        flag += h[solution2[i, j]]
flag += "}"
print(flag)

# flag{328059c335ba44eef6bc269996101901bb046bd87fe49118d0e2308ecda708487bee2790f11c2506}