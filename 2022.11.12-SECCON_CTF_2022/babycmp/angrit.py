#!/usr/bin/env python3
import angr
import claripy
import IPython

elf = 'chall.baby'
p = angr.Project(elf)
flag = claripy.BVS('flag', 512)
s = p.factory.entry_state(args=[elf, flag])
simgr = p.factory.simgr(s)
simgr.explore(find=[0x4012cc], avoid=[0x40127d])
IPython.embed()
# In [4]: simgr.stashes['found'][0].solver.eval(flag, cast_to=bytes)
# Out[4]: b'SECCON{y0u_f0und_7h3_baby_flag_YaY}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
