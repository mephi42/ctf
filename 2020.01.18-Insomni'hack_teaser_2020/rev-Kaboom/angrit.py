#!/usr/bin/env python3
import angr
import claripy

p = angr.Project('kaboom.exe')
state = p.factory.entry_state(addr=0x46f109)
flag_addr = 0x12340000
flag_len = 64
flag_bytes = []
for i in range(flag_len):
    flag_byte = claripy.BVS(f'flag[{i}]', 8)
    state.mem[flag_addr + i].uint8_t = flag_byte
    if i < 12:
        state.add_constraints(flag_byte != 0)
state.regs.eax = flag_addr
simgr = p.factory.simgr(state)
simgr.explore(find=[0x46f13f], avoid=[0x46f15b])
