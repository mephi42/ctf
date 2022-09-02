#!/usr/bin/env python3
import pysimulavr


STOP_PROGRAM = 0x4D0
MULTIPLY = 0xEC
MULTIPLY_LOOP = 0x123
ADD = 0x5F
SUB = 0x79
COMPARE = 0xD2
SYMBOLS = {
    0xA3: " (printHex)",
    MULTIPLY: " (multiply)",
    MULTIPLY_LOOP: " (multiply - second loop header)",
    ADD: " (add)",
    SUB: " (sub)",
    COMPARE: " (compare)",
}
UART_PUTCHAR = 0x189
N = 0x100
A = 0x120
FLAG = 0x140
RESULT = 0x1A4
MAIN = 0x174


def dump_value(dev, name, addr):
    print(name + "=" + bytes(dev.GetRWMem(addr + i) for i in range(0x20)).hex())


def sim_all(sc, dev):
    out = b""
    i = 0
    prev_pc = None
    while True:
        if dev.PC != prev_pc and dev.PC in SYMBOLS:
            print(SYMBOLS[dev.PC])
        # print(f"[{i}] pc=0x{dev.PC:x}{SYMBOLS.get(dev.PC, '')}")
        if prev_pc != MAIN and dev.PC == MAIN:
            dump_value(dev, "N", N)
            dump_value(dev, "A", A)
            dump_value(dev, "FLAG", FLAG)
        if dev.PC == STOP_PROGRAM:
            break
        if prev_pc != UART_PUTCHAR and dev.PC == UART_PUTCHAR:
            out += bytes((dev.GetCoreReg(24),))
        if prev_pc != MULTIPLY_LOOP and dev.PC == MULTIPLY_LOOP:
            dump_value(dev, "RESULT", RESULT)
        if (prev_pc != ADD and dev.PC == ADD) or (prev_pc != SUB and dev.PC == SUB):
            arg1 = (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24)
            arg2 = (dev.GetCoreReg(23) << 8) | dev.GetCoreReg(22)
            arg3 = (dev.GetCoreReg(21) << 8) | dev.GetCoreReg(20)
            print(f"ARG1=0x{arg1:x} ARG2=0x{arg2:x} ARG3=0x{arg3:x}")
        if prev_pc != COMPARE and dev.PC == COMPARE:
            arg1 = (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24)
            arg2 = (dev.GetCoreReg(23) << 8) | dev.GetCoreReg(22)
            print(f"ARG1=0x{arg1:x} ARG2=0x{arg2:x}")
        prev_pc = dev.PC
        sc.Step()
        i += 1
    print(out)
    dump_value(dev, "RESULT", RESULT)
    # Welcome to easy mode! The encrypted flag is:
    # 0x5c43a2adcea9625e48fd83ead700bf5864f7540ded4011677fcb61c3c94a8b3c
    # 3c8b4ac9c361cb7f671140ed0d54f76458bf00d7ea83fd485e62a9ceada2435c


sc = pysimulavr.SystemClock.Instance()
sc.ResetClock()
dev = pysimulavr.AvrFactory.instance().makeDevice("atmega128")
# dev = pysimulavr.AvrFactory.instance().makeDevice('at90can128')
# dev = pysimulavr.AvrDevice_at90can128()
dev.Load("scandinavia.elf")
dev.SetClockFreq(250)
sc.Add(dev)
sim_all(sc, dev)
