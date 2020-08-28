#!/usr/bin/env python3
from collections import defaultdict

# make python
# make build
# cd build/pysimulavr && python3 setup.py install --user
import _pysimulavr
import pysimulavr

REG_ALIASES = {
    'r24': 'Wlo',
    'r25': 'Whi',
    'r26': 'Xlo',
    'r27': 'Xhi',
    'r28': 'Ylo',
    'r29': 'Yhi',
    'r30': 'Zlo',
    'r31': 'Zhi',
}


def reg_name(r):
    return REG_ALIASES.get(r, r)


REGS = ['pc', 'H', 'V', 'N', 'S', 'Z', 'C', 'SP'] + [f'r{i}' for i in range(32)]
STATE_KEYS = [reg_name(reg) for reg in REGS]


def get_state(dev):
    state = {
        reg_name('pc'): dev.PC,
        reg_name('H'): dev.status.H,
        reg_name('V'): dev.status.V,
        reg_name('N'): dev.status.N,
        reg_name('S'): dev.status.S,
        reg_name('Z'): dev.status.Z,
        reg_name('C'): dev.status.C,
        reg_name('SP'): dev.stack.GetStackPointer(),
    }
    for i in range(32):
        state[reg_name(f'r{i}')] = dev.GetCoreReg(i)
    return state


def diff_state(old_state, new_state):
    result = []
    for key in STATE_KEYS:
        old_value = old_state[key]
        new_value = new_state[key]
        if old_value != new_value:
            result.append(f'{key}: 0x{old_value:x} -> 0x{new_value:x}')
    return ', '.join(result)


def read_asciz(dev, mem):
    s = ''
    while True:
        ch = dev.GetRWMem(mem)
        if ch == 0:
            break
        s += chr(ch)
        mem += 1
    return s


def ret():
    pass


FLAG = ''


def sim_hook(sc, dev):
    if dev.PC == 0x23b:  # delay() entry
        ms = ((dev.GetCoreReg(25) << 24) | (dev.GetCoreReg(24) << 16) |
              (dev.GetCoreReg(23) << 8) | dev.GetCoreReg(22))
        print(f'delay({ms=}')
        dev.PC = 0x26c  # delay() exit
        return True
    if dev.PC == 0x199:  # digitalWrite() entry
        pin = dev.GetCoreReg(24)
        val = dev.GetCoreReg(22)
        print(f'digitalWrite({pin=}, {val=})')
        dev.PC = 0x1c1  # digitalWrite() exit
        return True
    if dev.PC == 0x26d:  # digitalWrite101010() entry
        pin = dev.GetCoreReg(24)
        print(f'digitalWrite101010({pin=})')
        dev.PC = 0x28c  # digitalWrite101010() exit
        return True
    if dev.PC == 0x536:  # inlined analogWrite()
        val = dev.GetCoreReg(17)
        print(f'analogWrite({val=})')
        return False
    if dev.PC == 0x503:
        val = ((dev.GetCoreReg(27) << 24) | (dev.GetCoreReg(26) << 16) |
               (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24))
        print(f'Breakpoint 1 ({val=})')
        return False
    if dev.PC == 0x50c:
        val = ((dev.GetCoreReg(23) << 24) | (dev.GetCoreReg(22) << 16) |
               (dev.GetCoreReg(21) << 8) | dev.GetCoreReg(20))
        print(f'Breakpoint 2 ({val=})')
        return False
    if dev.PC == 0x519:
        print(f'Breakpoint 3')
        return False
    if dev.PC == 0x10d:
        val = chr(dev.GetCoreReg(18))
        global FLAG
        FLAG = FLAG + val
        print(f'Breakpoint 4 ({val=}, {FLAG=})')
        return False
    return False


def sim_all(sc, dev):
    i = 0
    prev_state = {'pc': -1}
    while True:
        state = get_state(dev)
        if state['pc'] != prev_state['pc']:
            action = sim_hook(sc, dev)
            if action is None:
                break
            if action:
                prev_state = state
                continue
        sc.Step()
        prev_state = state
        state = get_state(dev)
        print(str(i) + ': ' + diff_state(prev_state, state))
        i += 1


if __name__ == '__main__':
    _pysimulavr.cvar.sysConHandler.SetTraceFile("/dev/stdout", 0x7fffffff)
    sc = pysimulavr.SystemClock.Instance()
    sc.ResetClock()
    # libsim/at90canbase.cpp:    rw[0x6E]= & timerIrq0->timsk_reg;
    # libsim/atmega1284abase.cpp:    rw[0x6E]= & timerIrq0->timsk_reg;
    # libsim/atmega2560base.cpp:    rw[0x6E]= & timerIrq0->timsk_reg;
    # libsim/atmega668base.cpp:    rw[0x6E]= & timerIrq0->timsk_reg;

    # libsim/atmega668base.cpp:    rw[0x44]= & timer0->tccra_reg;
    # libsim/atmega668base.cpp:    rw[0x45]= & timer0->tccrb_reg;

    dev = pysimulavr.AvrFactory.instance().makeDevice('atmega328')  # at90can32
    dev.Load('flash.elf')
    dev.SetClockFreq(250)
    sc.Add(dev)
    # sc.SetTraceModeForAllMembers(1)
    sim_all(sc, dev)

# ractf{DidYouDoAnalysis?}
