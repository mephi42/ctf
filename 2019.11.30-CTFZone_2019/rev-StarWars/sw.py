#!/usr/bin/env python3
import json

import angr
from archinfo.arch_amd64 import ArchAMD64
from angr.calling_conventions import SimCCMicrosoftAMD64
from angr.procedures.libc.strncpy import strncpy
from angr.procedures.libc.malloc import malloc

threads = []


class CreateThread(angr.SimProcedure):
    def run(self, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
        threads.append(int(lpStartAddress.ast.args[0]))


waits = []


class WaitForSingleObject(angr.SimProcedure):
    def run(self, hHandle, dwMilliseconds):
        waits.append(1)


def get_str(state, addr):
    s = b''
    while True:
        b = state.solver.eval(state.mem[addr + len(s)].char.resolved)
        if b == 0:
            break
        s += bytes((b,))
    return s.decode()


def get_bytes(state, addr, n):
    s = b''
    for _ in range(n):
        s += bytes((state.solver.eval(state.mem[addr + len(s)].char.resolved),))
    return s


p = angr.Project('StarWars.exe')
cc = SimCCMicrosoftAMD64(ArchAMD64())
p.hook_symbol('CreateThread', CreateThread(cc=cc))
p.hook_symbol('WaitForSingleObject', WaitForSingleObject(cc=cc))
strncpy_addr = 0x14001a5b0
p.hook(strncpy_addr, strncpy(cc=cc))
p.hook(0x140011a68, malloc(cc=cc))

state = p.factory.call_state(0x140002100)  # init_npcs
simgr = p.factory.simgr(state)
simgr.explore(find=0x1400024fb)  # init_npcs ret
state, = simgr.stashes['found']
npcs = []
for i in range(0x10):
    npc_ptr = state.solver.eval(state.mem[0x14004cc80 + i * 8].long.resolved)
    npc = {
        'name': get_str(state, npc_ptr),
        'shield': state.solver.eval(state.mem[npc_ptr + 0x100].int.resolved),
        'attack': state.solver.eval(state.mem[npc_ptr + 0x104].char.resolved),
    }
    npcs.append(npc)

state = p.factory.call_state(0x140003120)  # init_game
simgr = p.factory.simgr(state)
simgr.explore()
players = []
for thread in threads:
    print('Thread 0x%016x' % thread)
    state = p.factory.call_state(thread)
    simgr = p.factory.simgr(state)
    ship = None
    player = None
    while True:
        simgr.step()
        for state in simgr.stashes['active']:
            ip = state.solver.eval(state.ip)
            if ip == strncpy_addr:
                continue
            if ship is None and state.history.jumpkind == 'Ijk_Call':
                ship = {
                    'name': get_str(state, state.regs.rcx + 8),
                    'shield': state.solver.eval(state.mem[state.regs.rcx + 0x108].int.resolved),
                    'attack': state.solver.eval(state.mem[state.regs.rcx + 0x10c].char.resolved),
                }
                continue
            if player is None and len(waits) > 0:
                waits.clear()
                player_npcs = get_bytes(state, state.regs.r11 - 0x58, 26)
                player = {
                    'ship': ship,
                    'npcs': list(player_npcs),
                }
        if player is not None:
            players.append(player)
            break

with open('sw.json', 'w') as fp:
    json.dump({
        'players': players,
        'npcs': npcs,
    }, fp, indent=4)
