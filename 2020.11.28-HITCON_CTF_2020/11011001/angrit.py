#!/usr/bin/env python3
import angr
import claripy
import IPython


def main():
    base = 0x400000
    p = angr.Project('11011001')
    init = True
    flag = []

    @p.hook(base + 0xc90)
    def __ZNSi10_M_extractIjEERSiRT_(state):
        assert init
        addr = state.solver.eval(state.regs.rsi)
        print(f'__ZNSi10_M_extractIjEERSiRT_(0x{addr:x})')
        for i in range(4):
            flag_byte = claripy.BVS(f'flag{len(flag)}', 8)
            state.mem[addr + i].uint8_t = flag_byte
            flag.append(flag_byte)
        state.regs.rsp += 8
        state.regs.pc = state.mem[state.regs.rsp - 8].uint64_t.resolved

    state = p.factory.call_state(addr=base + 0xcb0)
    simgr = p.factory.simgr(state)
    while True:
        state, = simgr.stashes['active']
        pc = state.solver.eval(state.regs.pc)
        print(f'0x{pc:x}')
        if pc == base + 0xd1c:
            break
        simgr.step()
    init = False
    simgr.explore(find=base + 0xf24, avoid=base + 0xd39)
    IPython.embed()
    # found, = simgr.stashes['found']
    # found.solver.eval_upto(claripy.Concat(*flag), 200, cast_to=bytes)
    # raw, = found.solver.eval_upto(claripy.Concat(*flag), 200, cast_to=bytes)
    # import struct
    # ' '.join(str(x) for x in struct.unpack('<' + 'I' * (len(raw) // 4), raw))
    # hitcon{fd05b10812d764abd7d853dfd24dbe6769a701eecae079e7d26570effc03e08d}


if __name__ == '__main__':
    main()
