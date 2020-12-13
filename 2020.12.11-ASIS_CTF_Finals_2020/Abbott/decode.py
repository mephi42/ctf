#!/usr/bin/env python3
import struct


# Black box analysis
#
# aaaaaaaaaaa:      00 02  cb 61
# aaaaaaaaaaaa:     00 02  cc 61
# bbbbbbbbbbb:      00 02  cb 62
# bbbbbbbbbbbb:     00 02  cc 62
# qxd:              00 04  a3 71(q) 78(x) 64(d)
# qxd_:             00 05  a4 71(q) 78(x) 64(d) 5f(_)
# qxd_o:            00 06  a5 71(q) 78(x) 64(d) 5f(_) 6f(o)
# a:                00 02  a1 61(a)
# aa:               00 03  a2 61(a) 61(a)
# aaa:              00 02  c3 61
# ab:               00 03  a2 61(a) 62(b)
# abc:              00 04  a3 61(a) 62(b) 63(c)
# abcd:             00 03  81 04 61(a)
# abcdqqqqq:        00 05  81 04 61 c5 71(q)
# CCCCC:            00 02  c5 43(C)
# qxd13qxd24qxd\n:  00 0f  a5! 71(q) 78(x) 64(d) 31(1) 33(3) e0! 03 a2! 32(2) 34(4) e0! 03 a1! 0a
# +++++++++++++++:  00 04  cf 2b
# ++++++++++++++++: 00 05  40 10 2b

# 00000000  01 02 02 15 20 20 00 c5  40 39 2b a9 0a 2b 2b 41  |....  ..@9+..++A|
#                                    !! LL RR !! LL SS SS SS
# 00000010  53 49 53 5f 5f 60 3c 0c  a5 43 54 46 5f 5f 60 4e  |SIS__`<..CTF__`N|
#           SS SS SS SS SS !! ?? ??  !! SS SS SS SS SS !! ??
# 00000020  1c c4 2b a1 0a c3 2b a2  4c 7a c3 30 a3 64 79 5f  |..+...+.Lz.0.dy_|
#           ?? !! RR !! SS !! RR !!  SS SS !! RR !! SS SS SS
# 00000030  60 77 28 c6 2b 60 73 04  a5 66 31 6c 65 5f 60 b1  |`w(.+`s..f1le_`.|
#           !! ?? ?? !! RR !! ?? ??  !! SS SS SS SS SS !! ??
# 00000040  2c c5 2b 60 73 04 a6 63  30 6d 70 52 33 c3 73 a2  |,.+`s..c0mpR3.s.|
#           ?? !! RR !! ?? ?? !! SS  SS SS SS SS SS !! RR !!
# 00000050  35 69 c4 30 a2 6e 5f 60  eb 19 60 f4 08 c4 2b 60  |5i.0.n_`..`...+`|
#           SS SS !! RR !! SS SS !!  ?? ?? !! ?? ?? !! RR ??
# 00000060  ad 05 ab 30 52 6d 41 37  5f 66 30 52 6d 41 61 2a  |...0RmA7_f0RmAa*|
#           ?? ?? !! SS SS SS SS SS  SS SS SS SS SS SS !! ??
# 00000070  25 c5 2b a1 0a 60 3c 04  a1 7b c3 5f 60 77 08 60  |%.+..`<..{._`w.`|
#           ?? !! RR !! SS !! ?? ??  !! SS !! RR !! ?? ?? !!
# 00000080  b1 04 a4 65 65 5f 63 c4  4f c3 4d a2 50 72 60 f0  |...ee_c.O.M.Pr`.|
#           ?? ?? !! SS SS SS SS !!  RR !! RR !! SS SS !! ??
# 00000090  0c a2 66 30 c3 52 a2 6d  41 c4 74 a1 7d 60 ad 05  |..f0.R.mA.t.}`..|
#           ?? !! SS SS !! RR !! SS  SS !! RR !! SS !! ?? ??
# 000000a0  a4 6c 61 67 5f 60 3c 05  a8 66 69 6c 33 5f 6a 30  |.lag_`<..fil3_j0|
#           !! SS SS SS SS !! ?? ??  !! SS SS SS SS SS SS SS
# 000000b0  64 c3 59 a2 5f 6a c3 30  a7 64 59 5f 5a 21 76 5f  |d.Y._j.0.dY_Z!v_|
#           SS !! RR !! SS SS !! RR  !! SS SS SS SS SS SS SS
# 000000c0  61 b6 10 c5 2b 60 73 04  40 36 2b a1 0a           |a...+`s.@6+..|
#           !! ?? ?? !! RR !! ?? ??  !! LL RR !! SS

def main():
    with open('flag.abbott', 'rb') as fp:
        encoded = fp.read()
    prefix = bytes.fromhex('01 02 02 15 20 20')
    assert encoded.startswith(prefix)
    i = len(prefix)
    the_len, = struct.unpack('>H', encoded[i: i + 2])
    i += 2
    assert i + the_len == len(encoded)
    decoded = b''
    while True:
        if i == len(encoded):
            break
        control = encoded[i]
        i += 1
        if (control & 0xf0) == 0x40:
            repeat_len = encoded[i]
            i += 1
            repeat_char = bytes((encoded[i],))
            i += 1
            decoded += repeat_char * repeat_len
        elif (control & 0xf0) == 0x60:
            copy_offset = encoded[i]
            i += 1
            copy_len = encoded[i]
            i += 1
            #decoded += f'{{0x{control:x},0x{copy_offset:x},0x{copy_len:x}}}'.encode()
            #decoded += decoded[copy_offset:copy_offset + copy_len]
            for ii in range(copy_len):
                decoded += bytes((decoded[copy_offset + ii],))
        elif (control & 0xf0) == 0x80:
            raise Exception('sequence of 15 bytes or less - not used')
        elif (control & 0xf0) == 0xa0:
            stored_len = (control & 0xf)
            decoded += encoded[i:i + stored_len]
            i += stored_len
        elif (control & 0xf0) == 0xc0:
            repeat_len = control & 0xf
            decoded += bytes((encoded[i],)) * repeat_len
            i += 1
        elif (control & 0xf0) == 0xe0:
            raise Exception('copy 15 bytes or less - not used')
        else:
            raise Exception(f'0x{control:2x}@0x{i:x}')
        print()
        print(decoded)
        print(decoded.decode())
        # ASIS{___Lz000dy_f1leee_cOOOOMMMPr3sss5i0000n_f0RRRmAtttt}


if __name__ == '__main__':
    main()
