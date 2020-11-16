#!/usr/bin/env python3
def f_1(i: int) -> int:
    counts = [1, 0, 0, 0]
    for i in range(i):
        counts = [
            counts[0] + counts[1] + counts[2] + counts[3],
            counts[0],
            counts[0],
            counts[0],
        ]
    return counts[1] + counts[2] * 2 + counts[3] * 3


def to_byte_array(n):
    result = bytearray()
    while n > 0:
        result.append(n & 0xff)
        n >>= 8
    return bytearray(reversed(result))


def main():
    a = bytearray(x & 0xff for x in [
        71, 20, -82, 84, -45, -4, 25, -122, 77, 63, -107, 13, -111, -43, 43,
        -42, 96, 38, -88, 20, -67, -40, 79, -108, 77, 8, -75, 80, -45, -69, 25,
        -116, 117, 106, -36, 69, -67, -35, 79, -114, 113, 36, -112, 87, -67,
        -2, 19, -67, 80, 42, -111, 23, -116, -55, 40, -92, 77, 121, -51, 86,
        -46, -85, 93,
    ])
    b = f_1(60107) % (2 ** 62)
    b = to_byte_array(b)
    flag = bytearray(a[i] ^ b[i % len(b)] for i in range(len(a)))
    flag = flag.decode()
    # The flag is BALSN{U_S01ved_this_W4rmUp_R3v_CH411eng!!!_W3lcom3_to_BalsnCTF_2020!!}
    print(f'The flag is BALSN{{{flag}}}')


if __name__ == '__main__':
    main()
