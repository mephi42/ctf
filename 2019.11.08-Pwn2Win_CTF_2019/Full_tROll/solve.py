#!/usr/bin/env python3
import angr
import claripy

p = angr.Project('full_troll', auto_load_libs=False)
base = 0x400000
password = claripy.BVS('password', 23 * 8)
sym_arg = claripy.Concat(password, claripy.BVV(0, 8))
s = p.factory.call_state(base + 0xa53, sym_arg)
sm = p.factory.simulation_manager(s)
sm.explore(
    find=base + 0xd3f,
    avoid=(base + 0xa79, base + base + 0xd38),
)
found = sm.stashes['found'][0]
password_chars = []
concrete_password = found.solver.eval(password)
for i in range(23):
    password_chars.append(chr(concrete_password & 0xff))
    concrete_password >>= 8
print(''.join(reversed(password_chars)))  # VibEv7xCXyK8AjPPRjwtp9X
