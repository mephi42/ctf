#!/usr/bin/env python3
import json
import pysimulavr


STOP_PROGRAM = 0x4D0
MULTIPLY = 0xEC
MULTIPLY_LOOP = 0x123
ADD = 0x5F
SUB = 0x79
COMPARE = 0xD2
UART_PUTCHAR = 0x189
N = 0x100
A = 0x120
FLAG = 0x140
RESULT = 0x1A4
MAIN = 0x174
WORK_FLAG = 0x8af
SYMBOLS = {
    0xA3: " (printHex)",
    MULTIPLY: " (multiply)",
    MULTIPLY_LOOP: " (multiply - second loop header)",
    ADD: " (add)",
    SUB: " (sub)",
    COMPARE: " (compare)",
    MAIN: " (main)",
}


def dump_value(dev, name, addr):
    print(name + "=" + bytes(dev.GetRWMem(addr + i) for i in range(0x20)).hex())


def sim_all(sc, dev):
    out = b""
    i = 0
    prev_pc = None
    branch = None
    branches = []
    while True:
        if dev.PC != prev_pc and dev.PC in SYMBOLS:
            print(SYMBOLS[dev.PC])
        if prev_pc != MAIN and dev.PC == MAIN:
            #dev.SetRWMem(N + 31, 0xff)
            dump_value(dev, "N", N)
            dump_value(dev, "A", A)
            dump_value(dev, "FLAG", FLAG)
        if dev.PC == STOP_PROGRAM:
            break
        if prev_pc != UART_PUTCHAR and dev.PC == UART_PUTCHAR:
            out += bytes((dev.GetCoreReg(24),))
        if prev_pc != MULTIPLY_LOOP and dev.PC == MULTIPLY_LOOP:
            print(f"BRANCH={branch}")
            dump_value(dev, "RESULT", RESULT)
            dump_value(dev, "WORK_FLAG", WORK_FLAG)
            if branch is not None:
                branches.append(branch)
            branch = ""
        if (prev_pc != ADD and dev.PC == ADD) or (prev_pc != SUB and dev.PC == SUB):
            arg1 = (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24)
            arg2 = (dev.GetCoreReg(23) << 8) | dev.GetCoreReg(22)
            arg3 = (dev.GetCoreReg(21) << 8) | dev.GetCoreReg(20)
            print(f"ARG1=0x{arg1:x} ARG2=0x{arg2:x} ARG3=0x{arg3:x}")
            dump_value(dev, "*ARG2", arg2)
            dump_value(dev, "*ARG3", arg3)
            branch += "a" if dev.PC == ADD else "s"
        if prev_pc != COMPARE and dev.PC == COMPARE:
            arg1 = (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24)
            arg2 = (dev.GetCoreReg(23) << 8) | dev.GetCoreReg(22)
            print(f"ARG1=0x{arg1:x} ARG2=0x{arg2:x}")
            dump_value(dev, "*ARG1", arg1)
            dump_value(dev, "*ARG2", arg2)
        prev_pc = dev.PC
        sc.Step()
        i += 1
    if branch is not None:
        branches.append(branch)
    prefix = b"Welcome to hard mode! The encrypted flag is:\n\r"
    suffix = b"\n\r"
    assert out.startswith(prefix)
    assert out.endswith(suffix)
    print(out)
    dump_value(dev, "RESULT", RESULT)
    print(
        json.dumps(
            {"result": out[len(prefix) : -len(suffix)].decode(), "branches": branches}
        )
    )


sc = pysimulavr.SystemClock.Instance()
sc.ResetClock()
dev = pysimulavr.AvrFactory.instance().makeDevice("atmega128")
dev.Load("scandinavia2.elf")
dev.SetClockFreq(250)
sc.Add(dev)
sim_all(sc, dev)
