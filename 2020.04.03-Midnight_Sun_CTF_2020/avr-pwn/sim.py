#!/usr/bin/env python3
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


STATE_KEYS = list(map(reg_name, ['pc', 'H', 'V', 'N', 'S', 'Z', 'C', 'SP'] + [f'r{i}' for i in range(32)]))


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


def groke():
    a = "\"%s\"" % ("a" * 20)
    res = []
    for i in range(44):
        res.append(a)
    return "[%s]" % ",".join(res)


def groke2():
    return '{0: "aaaaaaaaaaaaaaaaaaaa", 1: "aaaaaaaaaaaaaaaaaaaa", 2: "aaaaaaaaaaaaaaaaaaaa", 3: "aaaaaaaaaaaaaaaaaaaa", 4: "aaaaaaaaaaaaaaaaaaaa", 5: "aaaaaaaaaaaaaaaaaaaa", 6: "aaaaaaaaaaaaaaaaaaaa", 7: "aaaaaaaaaaaaaaaaaaaa", 8: "aaaaaaaaaaaaaaaaaaaa", 9: "aaaaaaaaaaaaaaaaaaaa", 10: "aaaaaaaaaaaaaaaaaaaa", 11: "aaaaaaaaaaaaaaaaaaaa", 12: "aaaaaaaaaaaaaaaaaaaa", 13: "aaaaaaaaaaaaaaaaaaaa", 14: "aaaaaaaaaaaaaaaaaaaa", 15: "aaaaaaaaaaaaaaaaaaaa", 16: "aaaaaaaaaaaaaaaaaaaa", 17: "aaaaaaaaaaaaaaaaaaaa", 18: "aaaaaaaaaaaaaaaaaaaa", 19: "aaaaaaaaaaaaaaaaaaaa", 20: "aaaaaaaaaaaaaaaaaaaa", 21: "aaaaaaaaaaaaaaaaaaaa", 22: "aaaaaaaaaaaaaaaaaaaa", 23: "aaaaaaaaaaaaaaaaaaaa", 24: "aaaaaaaaaaaaaaaaaaaa", 25: "aaaaaaaaaaaaaaaaaaaa", 26: "aaaaaaaaaaaaaaaaaaaa", 27: "aaaaaaaaaaaaaaaaaaaa", 28: "aaaaaaaaaaaaaaaaaaaa", 29: "aaaaaaaaaaaaaaaaaaaa", 30: "aaaaaaaaaaaaaaaaaaaa", 31: "aaaaaaaaaaaaaaaaaaaa", 32: "aaaaaaaaaaaaaaaaaaaa", 33: "aaaaaaaaaaaaaaaaaaaa", 34: "aaaaaaaaaaaaaaaaaaaa", 35: "aaaaaaaaaaaaaaaaaaaa", 36: "aaaaaaaaaaaaaaaaaaaa", 37: "aaaaaaaaaaaaaaaaaaaa", 38: "aaaaaaaaaaaaaaaaaaaa", 39: "aaaaaaaaaaaaaaaaaaaa", 40: "aaaaaaaaaaaaaaaaaaaa", 41: "aaaaaaaaaaaaaaaaaaaa", 42: "aaaaaaaaaaaaaaaaaaaa", 43: "aaaaaaaaaaaaaaaaaaaa", 44: "aaaaaaaaaaaaaaaaaaaa", 45: "aaaaaaaaaaaaaaaaaaaa", 46: "aaaaaaaaaaaaaaaaaaaa", 47: "aaaaaaaaaaaaaaaaaaaa", 48: "aaaaaaaaaaaaaaaaaaaa", 49: "aaaaaaaaaaaaaaaaaaaa", 50: "aaaaaaaaaaaaaaaaaaaa", 51: "aaaaaaaaaaaaaaaaaaaa", 52: "aaaaaaaaaaaaaaaaaaaa", 53: "aaaaaaaaaaaaaaaaaaaa", 54: "aaaaaaaaaaaaaaaaaaaa", 55: "aaaaaaaaaaaaaaaaaaaa", 56: "aaaaaaaaaaaaaaaaaaaa", 57: "aaaaaaaaaaaaaaaaaaaa", 58: "aaaaaaaaaaaaaaaaaaaa", 59: "aaaaaaaaaaaaaaaaaaaa", 60: "aaaaaaaaaaaaaaaaaaaa", 61: "aaaaaaaaaaaaaaaaaaaa", 62: "aaaaaaaaaaaaaaaaaaaa", 63: "aaaaaaaaaaaaaaaaaaaa"}'


def gr_3(x):
    a = "%s" % ("a" * 29)
    res = {}
    idx = 0
    for i in range(x):
        res[i] = a
    val = "%s" % repr(res)
    return val.replace("'", "\"")


def nested(depth):
    s = ''
    for _ in range(depth):
        s += '{0:'
    s += '0'
    for _ in range(depth):
        s += '}'
    return s


def gr44():
    return b'{0: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2: "ccccccccccccccccccccccccccccc", 3: "ddddddddddddddddddddddddddddd", 4: "eeeeeeeeeeeeeeeeeeeeeeeeeeeee", 5: "fffffffffffffffffffffffffffff", 6: "ggggggggggggggggggggggggggggg", 7: "hhhhhhhhhhhhhhhhhhhhhhhhhhhhh", 8: "iiiiiiiiiiiiiiiiiiiiiiiiiiiii", 9: "jjjjjjjjjjjjjjjjjjjjjjjjjjjjj", 10: "kkkkkkkkkkkkkkkkkkkkkkkkkkkkk", 11: "lllllllllllllllllllllllllllll", 12: "mmmmmmmmmmmmmmmmmmmmmmmmmmmmm", 13: "nnnnnnnnnnnnnnnnnnnnnnnnnnnnn", 14: "ooooooooooooooooooooooooooooo", 15: "ppppppppppppppppppppppppppppp", 16: "qqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 17: "rrrrrrrrrrrrrrrrrrrrrrrrrrrrr", 18: "sssssssssssssssssssssssssssss", 19: "ttttttttttttttttttttttttttttt", 20: "uuuuuuuuuuuuuuuuuuuuuuuuuuuuu", 21: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvv", 22: "wwwwwwwwwwwwwwwwwwwwwwwwwwwww", 23: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 24: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 25: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 26: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 27: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 28: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 29: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDD", 30: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEE", 31: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 32: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGG", 33: "HHHHHHHHHHHHHHHHHHHHHHHHHHHHH", 34: "\x01\x82\x00#\x20\x20\x02\x02\x20\x01l?\xff\xff\xff\xff\xff\xff\x08\xc3\x08\xc3\x08\xc3\x08\xc3\x08\xc3?"}'


# chars = list('{1337:"flag"}\n')
# chars = list(groke() + "\n")
# chars = list(nested(100000) + "\n")
# chars = list(groke2() + "\n")
# chars = list(gr_3(100) + "\n")
chars = list(gr44())
actually_read = list()


def read_str(sc, dev, mem):
    s = ''
    while True:
        ch = dev.GetRWMem(mem)
        if ch == 0:
            break
        s += chr(ch)
        mem += 1
    return s


def sim_hook(sc, dev):
    global chars
    if dev.PC == 0x52c:
        ch = chars[0]
        print(f'PARSE getchar({repr(ch)})')
        chars = chars[1:]
        actually_read.append(ch)
        dev.SetCoreReg(24, ch)
        dev.SetCoreReg(25, 0)
        dev.PC = 0x569
        return True
    if dev.PC == 0x5a6:
        mem = dev.GetCoreReg(24) | (dev.GetCoreReg(25) << 8)
        s = read_str(sc, dev, mem)
        print(f'OUT printf({repr(s)}@0x{mem:x})')
        dev.PC = 0x8c2
        return True
    if dev.PC == 0x5c3:
        mem = dev.GetCoreReg(24) | (dev.GetCoreReg(25) << 8)
        s = read_str(sc, dev, mem)
        print(f'OUT puts({repr(s)}@0x{mem:x})')
        dev.PC = 0x5f2
        return True
    if dev.PC == 0x56a:
        ch = chr(dev.GetCoreReg(24))
        print(f'OUT putchar({repr(ch)})')
        dev.PC = 0x5a5
        return True
    if dev.PC == 0x8c3:
        return None
    if dev.PC == 0x137:
        print('PARSE getany')
        return False
    if dev.PC == 0x18a:
        print('PARSE getlist')
        return False
    if dev.PC == 0x1ae:
        print('PARSE getdict')
        return False
    if dev.PC == 0x79:
        print('PARSE gettoken')
        return False
    if dev.PC == 0x136:
        token = dev.GetCoreReg(24)
        print(f'PARSE gettoken -> {token}')
        return False
    if dev.PC == 0x5f3:
        ch = dev.GetCoreReg(24)
        chars = [ch] + chars
        actually_read.pop()
        print(f'PARSE ungetc({repr(ch)})')
        dev.PC = 0x60b
        return True
    if dev.PC == 0x3b7:
        n = dev.GetCoreReg(24) | (dev.GetCoreReg(25) << 8)
        print(f'PARSE malloc({n})')
        return False
    if dev.PC == 0x44e:
        p = dev.GetCoreReg(24) | (dev.GetCoreReg(25) << 8)
        print(f'PARSE malloc -> 0x{p:x}')
        return False
    return False


def sim_all(sc, dev):
    i = 0
    state = get_state(dev)
    while True:
        action = sim_hook(sc, dev)
        if action is None:
            break
        if action:
            continue
        sc.Step()
        new_state = get_state(dev)
        print(str(i) + ': ' + diff_state(state, new_state))
        state = new_state
        i += 1


sc = pysimulavr.SystemClock.Instance()
sc.ResetClock()
dev = pysimulavr.AvrFactory.instance().makeDevice('atmega128')
dev.Load('challenge.elf')
dev.SetClockFreq(250)
sc.Add(dev)
sim_all(sc, dev)
print(''.join(chr(x) for x in actually_read))
