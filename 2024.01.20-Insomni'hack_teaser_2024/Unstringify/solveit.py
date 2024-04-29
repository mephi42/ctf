# https://github.com/boppreh/aes/blob/c8e889603f22f964fbdf62d64e1f95bed83bf832/aes.py
from aes import (
    bytes2matrix,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    matrix2bytes,
    xor_bytes,
)


# VAESENC (EVEX Encoded Version)
# (KL,VL) = (1,128), (2,256), (4,512)
# FOR i := 0 to KL-1:
#     STATE := SRC1.xmm[i] // xmm[i] is the i’th xmm word in the SIMD register
#     RoundKey := SRC2.xmm[i]
#     STATE := ShiftRows( STATE )
#     STATE := SubBytes( STATE )
#     STATE := MixColumns( STATE )
#     DEST.xmm[i] := STATE XOR RoundKey
# DEST[MAXVL-1:VL] := 0


def main():
    key = bytes(
        map(
            lambda x: int(x, 0),
            """
0x00 0x03 0x19 0x5a 0x5b 0x00 0x59 0x02
0x00 0x03 0x15 0x01 0x5c 0x09 0x01 0x5e
0x42 0x53 0x0d 0x16 0x4d 0x06 0x42 0x0d
0x27 0x52 0x42 0x3a 0x63 0x0b 0x54 0x0f
""".split(),
        )
    )
    enc = bytearray(
        map(
            lambda x: int(x, 0),
            """
0x51 0xcc 0x0f 0xbe 0xa0 0x26 0x2a 0x14
0x6d 0x75 0x89 0x30 0xec 0xfd 0x46 0x1c
0x0f 0xa3 0xb4 0x79 0x8b 0x62 0xc9 0x06
0x68 0xea 0x03 0xbe 0x2a 0xc7 0xf2 0xc4
""".split(),
        )
    )
    for i in (0, 16):
        state = bytes2matrix(xor_bytes(enc[i : i + 16], key[i : i + 16]))
        inv_mix_columns(state)
        inv_sub_bytes(state)
        inv_shift_rows(state)
        enc[i : i + 16] = matrix2bytes(state)
    print(enc)  # INS{T45k_Sp0n$0r3d_By_G4l4h4d<3}


if __name__ == "__main__":
    main()
