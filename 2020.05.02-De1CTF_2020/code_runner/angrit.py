import os

import angr
import claripy


def get_single_active_state(simgr):
    active = simgr.stashes['active']
    if len(active) == 0:
        raise Exception('No active states')
    if len(active) != 1:
        pcs = [state.regs.pc for state in active]
        raise Exception(f'Multiple active states: {pcs}')
    state, = active
    return state


def step_until_pc(simgr, until):
    while True:
        state = get_single_active_state(simgr)
        pc = state.solver.eval(state.regs.pc)
        print(f'pc: 0x{pc:x}')
        if pc in until:
            return state
        simgr.step()


def get_str(state, addr):
    s = b''
    while True:
        b = state.solver.eval(state.mem[addr + len(s)].char.resolved)
        if b == 0:
            break
        s += bytes((b,))
    return s.decode()


def step_until_puts(p, simgr, arg):
    puts_addr = p.loader.find_symbol('puts').rebased_addr
    while True:
        state = step_until_pc(simgr, (puts_addr,))
        actual = get_str(state, state.regs.a0)
        print(f'puts("{actual}")')
        if actual == arg:
            return state
        simgr.step()


def step_until_read(p, simgr):
    read_addr = p.loader.find_symbol('read').rebased_addr
    return step_until_pc(simgr, (read_addr,))


def step_until_call(simgr):
    while True:
        state = get_single_active_state(simgr)
        pc = state.solver.eval(state.regs.pc)
        jk = state.history.jumpkind
        print(f'pc: 0x{pc:x}, jk: {jk}')
        if jk == 'Ijk_Call':
            return state
        simgr.step()


def solve(path):
    p = angr.Project(path)
    read_addr = p.loader.find_symbol('read').rebased_addr
    entry_state = p.factory.entry_state()
    simgr = p.factory.simgr(entry_state)
    step_until_puts(p, simgr, 'Faster > ')
    state_at_read = step_until_pc(simgr, (read_addr,))
    assert state_at_read.solver.eval(state_at_read.regs.a0) == 0
    user_buf_addr = state_at_read.solver.eval(state_at_read.regs.a1)
    assert state_at_read.solver.eval(state_at_read.regs.a2) == 0x100
    user_bytes = [claripy.BVS(f'x{i}', 8) for i in range(0x100)]
    for i, user_byte in enumerate(user_bytes):
        state_at_read.mem[user_buf_addr + i].char = user_byte
    state_at_read.regs.v0 = 0x100
    state_at_read.regs.pc = state_at_read.regs.ra
    simgr = p.factory.simgr(state_at_read)
    simgr.step()
    step_until_call(simgr)
    simgr.step()
    state_at_checker = step_until_call(simgr)
    while True:
        pc = state_at_checker.solver.eval(state_at_checker.regs.pc)
        print(f'checker pc: 0x{pc:x}')

        # some checkers are nonlinear and confuse z3
        # try silly solutions first
        state_at_checker_silly = state_at_checker.copy()
        for i in range(4):
            ch_addr = state_at_checker_silly.regs.a0 + i
            ch = state_at_checker_silly.mem[ch_addr].char.resolved
            state_at_checker_silly.add_constraints(ch < 2)
        simgr_silly = p.factory.simgr(state_at_checker_silly)
        simgr_silly.step()
        simgr_silly.explore(
            find=lambda state: state.history.jumpkind == 'Ijk_Call',
            avoid=lambda state: state.history.jumpkind == 'Ijk_Ret',
        )
        if len(simgr_silly.stashes['found']) > 0:
            state_at_checker = simgr_silly.stashes['found'][0]
            simgr = p.factory.simgr(state_at_checker)
            continue

        simgr.step()
        simgr.explore(
            find=lambda state: state.history.jumpkind == 'Ijk_Call',
            avoid=lambda state: state.history.jumpkind == 'Ijk_Ret',
        )
        if len(simgr.stashes['found']) > 0:
            state_at_checker, = simgr.stashes['found']
            simgr = p.factory.simgr(state_at_checker)
            continue
        break
    return bytes(
        state_at_checker.solver.eval(user_byte)
        for user_byte in user_bytes
    )


if __name__ == '__main__':
    for i in os.listdir('samples'):
        print(solve(f'samples/{i}').hex())
