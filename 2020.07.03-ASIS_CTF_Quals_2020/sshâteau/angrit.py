#!/usr/bin/env python3
import angr
import claripy
import IPython


def main():
    project = angr.Project('sshateau/sshd')
    username = 'reuben'
    password = [claripy.BVS(f'flag{i}', 8) for i in range(34)]
    base = 0x400000
    state = project.factory.call_state(
        base + 0xf5a0, username, password + [claripy.BVV(0, 8)])
    for c in password:
        state.add_constraints(c >= 0x20)
        state.add_constraints(c <= 0x7f)
    simgr = project.factory.simgr(state)
    simgr.explore(find=base + 0xfab2, avoid=(base + 0xf6a1, base + 0xf75b))
    IPython.embed()
    # found, = simgr.stashes['found']
    # found.solver.eval_upto(claripy.Concat(*password), 200, cast_to=bytes)
    # [b'CgaGeIm5z;qOkgSYqDhbHfJn6{<rPlhTZr', b'CSaGeIm5z;qOkggYqDTbHfJn6{<rPlhhZr']
    # ASIS{F0r_ev3ry_0ne_th4t_a5ke7h_r3ceive7h_4nd_h3_th4t_s33ke7h_f1nde7h_4nd_t0_h1m_th4t_kn0cke7h_1t_5hall_8e_0pen3d}


if __name__ == '__main__':
    main()
