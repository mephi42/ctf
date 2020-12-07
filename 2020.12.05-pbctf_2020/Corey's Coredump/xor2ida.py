#!/usr/bin/env python3
import os
import re


# grep -e '0x000022e5: MT_LOAD' -e '0x000022e5: MT_GET_REG rax' -e '0x00002310: MT_LOAD' -e '0x00002310: MT_GET_REG rax' <memtrace.txt >xor.txt
def main():
    print('import struct')
    print()
    print('from ida_bytes import get_bytes, patch_bytes')
    print()
    processed = {
        0x5555555552c2, 0x5555555552c6,
        0x555555555492, 0x555555555496,
        0x555555555d65, 0x555555555d69,
    }
    seen = set()
    with open(os.path.expanduser('~/myrepos/memtrace/xor.txt')) as fp:
        while True:
            # [  10443860] 0x000022e5: MT_LOAD uint32_t [0x555555555ce5] 0x113f832
            l1 = fp.readline().strip()
            # [  10443861] 0x000022e5: MT_GET_REG rax 0x7165737a
            l2 = fp.readline().strip()
            if l1 == '' or l2 == '':
                break
            seq1, addr = re.match(r'\[..........] (0x[0-9a-f]{8}): MT_LOAD uint32_t \[(0x[0-9a-f]+)]', l1).groups()
            seq2, rax = re.match(r'\[..........] (0x[0-9a-f]{8}): MT_GET_REG rax (0x[0-9a-f]+)', l2).groups()
            seq1 = int(seq1, 0)
            addr = int(addr, 0)
            seq2 = int(seq2, 0)
            rax = int(rax, 0)
            assert seq1 == seq2
            if addr not in seen:
                if seq1 == 0x000022e5:
                    print(f'patch_bytes(0x{addr - 3:x}, b\'\\x90\\x90\\x90\')')
                else:
                    assert seq1 == 0x00002310
                if addr not in processed:
                    print(f'patch_bytes(0x{addr:x}, struct.pack(\'<I\', struct.unpack(\'<I\', get_bytes(0x{addr:x}, 4))[0] ^ 0x{rax:x}))')
                seen.add(addr)
        print('print(\'Done\')')


if __name__ == '__main__':
    main()
