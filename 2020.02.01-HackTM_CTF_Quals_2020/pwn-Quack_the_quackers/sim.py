#!/usr/bin/env python3
from collections import defaultdict

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


STATE_KEYS = list(map(reg_name, ['pc', 'H', 'V', 'N', 'S', 'Z', 'C'] + [f'r{i}' for i in range(32)]))


def get_state(dev):
    state = {
        reg_name('pc'): dev.PC,
        reg_name('H'): dev.status.H,
        reg_name('V'): dev.status.V,
        reg_name('N'): dev.status.N,
        reg_name('S'): dev.status.S,
        reg_name('Z'): dev.status.Z,
        reg_name('C'): dev.status.C,
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


def sim_all(sc, dev):
    i = 0
    state = get_state(dev)
    seen = defaultdict(int)
    while True:
        seen[dev.PC] += 1
        if seen[dev.PC] > 1000:
            break
        sc.Step()
        if state['pc'] in (0x5b9, 0x653):
            print('Force W=1 in order to skip a useless loop')
            dev.SetCoreReg(24, 1)
            dev.SetCoreReg(25, 0)
        new_state = get_state(dev)
        print(str(i) + ': ' + diff_state(state, new_state))
        state = new_state
        i += 1


def sim_f_a(sc, dev, y):
    dev.PC = 0x89c
    dev.SetCoreReg(23, (y >> 8) & 0xff)
    dev.SetCoreReg(22, y & 0xff)
    dev.SetCoreReg(25, (y >> 8) & 0xff)
    dev.SetCoreReg(24, y & 0xff)
    i = 0
    state = get_state(dev)
    while True:
        if dev.PC == 0x8ac:
            break
        sc.Step()
        new_state = get_state(dev)
        print(str(i) + ': ' + diff_state(state, new_state))
        state = new_state
        i += 1
    return (dev.GetCoreReg(25) << 8) | dev.GetCoreReg(24)


sc = pysimulavr.SystemClock.Instance()
sc.ResetClock()
dev = pysimulavr.AvrFactory.instance().makeDevice('attiny85')
dev.Load('quack_the_quackers.elf')
dev.SetClockFreq(250)
sc.Add(dev)

for y in (0, 0x1234, 0xffff):
    print(f'f_a(0x{y:x}) = ...')
    w = sim_f_a(sc, dev, y)
    print(f'f_a(0x{y:x}) = 0x{w:x}')
