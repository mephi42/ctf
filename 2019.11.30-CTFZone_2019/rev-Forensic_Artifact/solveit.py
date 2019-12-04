#!/usr/bin/env pypy3
import logging

# logging.getLogger('angr.sim_manager').setLevel(logging.INFO)
import angr
import claripy
from angr.sim_procedure import SimProcedure
from angr.procedures.libc.memcmp import memcmp


class Puts(SimProcedure):
    def run(self, s):
        print(s)


def get_bytes(state, addr, n):
    s = b''
    for _ in range(n):
        s += bytes((state.solver.eval(state.mem[addr + len(s)].char.resolved),))
    return s


class MemCmp(memcmp):
    def run(self, s1, s2, n):
        ret = memcmp.run(self, s1, s2, n)

        n_val = self.state.solver.eval(n)
        s1_val = get_bytes(self.state, s1, n_val)
        s2_val = get_bytes(self.state, s2, n_val)
        ret_val = self.state.solver.eval(ret)
        print('memcmp(%s, %s, %s) = %s' % (s1_val, s2_val, n_val, ret_val))

        return ret


p = angr.Project('libpackstr.so', main_opts={
    'base_addr': 0x10000,
})
p.hook_symbol('puts', Puts())
p.hook_symbol('memcmp', MemCmp())


@p.hook(0x10bfc)
def call_func_blocked(state):
    print('call_func_blocked: a0=' + str(state.regs.a0) + ', a1=' + str(state.regs.a1))


@p.hook(0x10ecc)
def call_func_by_index(state):
    print('call_func_by_index: a0=' + str(state.regs.a0) + ', a1=' + str(state.regs.a1) + ', a1=' + str(state.regs.a2))


@p.hook(0x1356c)
def conv_0x0a(state):
    print('conv_0x0a')


@p.hook(0x155a4)
def conv_0x14(state):
    print('conv_0x14')


magic_start = 0x26260
cfb_start = 0x10bfc
cfb_ret = 0x10ec4
dummy_ptr = 0xfff0000
dummy_ptr2 = 0xeee0000
length = 0x2a


def dump_objs(state, first_addr, last_addr, first_len, last_len):
    x = first_addr
    y = first_len
    result = b''
    while x <= last_addr and y <= last_len:
        ptr_val = state.solver.eval(state.mem[x].int.resolved)
        len_val = state.solver.eval(state.mem[y].int.resolved)
        result += get_bytes(state, ptr_val, len_val)
        x += 4
        y += 4
    return result


def bk(exp):
    length = len(exp)
    dummy = claripy.BVS('input', length * 8)
    state = p.factory.call_state(cfb_start, dummy_ptr, length)
    state.regs.t9 = cfb_start
    state.memory.store(dummy_ptr, dummy)
    simgr = p.factory.simgr(state)
    simgr.explore(find=cfb_ret)
    state, = simgr.found
    for i, b in enumerate(exp):
        ch = state.mem[dummy_ptr + i].char.resolved
        cons = ch == claripy.BVV(b, 8)
        #print('CONS ' + str(cons))
        state.solver.add(cons)
    return state.solver.eval(dummy, cast_to=bytes)


def fw(val):
    length = len(val)
    state = p.factory.call_state(cfb_start, dummy_ptr, length)
    state.regs.t9 = cfb_start
    state.memory.store(dummy_ptr, val)
    simgr = p.factory.simgr(state)
    simgr.explore(find=cfb_ret)
    state, = simgr.found
    return get_bytes(state, dummy_ptr, length)


def fw_one(val, conv_XXX, conv_YYY):
    length = len(val)
    state = p.factory.call_state(conv_XXX, dummy_ptr, dummy_ptr2, length)
    state.regs.t9 = conv_XXX
    state.memory.store(dummy_ptr, val)
    simgr = p.factory.simgr(state)
    simgr.explore(find=conv_YYY)
    state, = simgr.found
    return get_bytes(state, dummy_ptr2, length)


if True:
    x = open('x.bin', 'rb').read()
    print('??? ' + str(len(x)) + ' ' + str(x))
    #x = fw_one(x, 0x12330, 0x12464)  # 2
    #print('??? ' + str(len(x)) + ' ' + str(x))
    x = fw_one(x, 0x01246c, 0x125f0)  # 3
    print('??? ' + str(len(x)) + ' ' + str(x))
    #x = fw_one(x, 0x12a2c, 0x12c2c)  # 6
    #print('??? ' + str(len(x)) + ' ' + str(x))
    x = fw_one(x, 0x012c34, 0x12dc0)  # 7
    print('??? ' + str(len(x)) + ' ' + str(x))
    #x = fw_one(x, 0x13ec0, 0x141d0)  # 14
    #print('??? ' + str(len(x)) + ' ' + str(x))


if False:
    x = open('all0', 'rb').read()
    print(fw(x))
    print(bk(x))
    x = open('all1', 'rb').read()
    print(fw(x))
    print(bk(x))


if False:
    state = p.factory.entry_state()
    exp = get_bytes(state, magic_start, length)
    print('EXP: ' + str(exp))
    with open('all0', 'wb') as fp:
        fp.write(dump_objs(state, 0x26308, 0x26344, 0x26348, 0x26384))
    sol = bk(exp)
    print('SOL: ' + str(sol))
    rep = 0
    for i in range(rep):
        sol = bk(sol)
        print('SOL: ' + str(sol))
    check = fw(sol)
    print('CHK: ' + str(check))
    for i in range(rep):
        check = fw(check)
        print('CHK: ' + str(check))
    assert check == exp
    with open('all1', 'wb') as fp:
        fp.write(dump_objs(state, 0x26290, 0x262c8, 0x262cc, 0x26304) + sol)

if False:
    input_string = claripy.BVS('input_string', 8 * 0x100)
    output_string = bytes(0x100)
    length = claripy.BVS('length', 32, 1, 0x100)
    pack_addr = 0x10ad4
    pack_ret_addr = 0x10ba8
    state = p.factory.call_state(pack_addr, input_string, output_string, length)
    state.regs.t9 = pack_addr  # report to angr? https://www.cr0.org/paper/mips.elf.external.resolution.txt
    simgr = p.factory.simgr(state)
    simgr.explore(find=pack_ret_addr)
    print('OK')
