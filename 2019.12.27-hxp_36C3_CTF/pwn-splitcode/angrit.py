#!/usr/bin/env pypy3
import angr

project = angr.Project('./vuln')


@project.hook(0x400277)
def sys_open_urandom(state):
    assert state.solver.eval(state.regs.rax == 2)
    state.regs.rax = 3
    state.regs.rip = state.regs.rip + 2


@project.hook(0x40028f)
def sys_read_urandom(state):
    assert state.solver.eval(state.regs.rax == 0)
    state.regs.rax = 0x1000
    state.regs.rip = state.regs.rip + 2


@project.hook(0x4002a3)
def sys_close_urandom(state):
    assert state.solver.eval(state.regs.rax == 3)
    state.regs.rax = 0
    state.regs.rip = state.regs.rip + 2


@project.hook(0x40032e)
def memset(state):
    assert state.solver.eval(state.regs.rcx == 0x1000)
    state.regs.rcx = 0
    state.regs.rdi = state.regs.rdi + 0x1000
    state.regs.rip = state.regs.rip + 2


@project.hook(0x40035b)
def syscall_check(state):
    state.regs.rip = state.regs.rip + 2


@project.hook(0x400362)
def int_check(state):
    state.regs.rip = state.regs.rip + 2


@project.hook(0x4003a4)
def user_call(state):
    pass


state = project.factory.entry_state()
simgr = project.factory.simgr(state)
while True:
    for i, active in enumerate(simgr.active):
        print(f'[{i}] rip = {active.regs.rip}')
    if len(simgr.active) != 1:
        raise Exception('FORKED')
    simgr.step()
