#!/usr/bin/env python3
import logging
import sys

from manticore import set_verbosity
from manticore.ethereum import ManticoreEVM, evm
from manticore.utils.config import get_group
get_group('evm').oog = 'ignore'

if len(sys.argv) > 1 and sys.argv[1] != 'DEBUG=1':
    localfile = sys.argv[1]
else:
    localfile = None
if localfile is None:
    import re
    from pwn import *

    p = remote('aab2596ac4a422a9f803ed317089c399b818bb72.balsnctf.com', 30731)
    m = re.search(r'sha256\((.+?) \+ \?\?\?\) == 0+\((\d+)\)', p.readline().decode())
    prefix = m.group(1)
    difficulty = int(m.group(2))
    zeros = '0' * difficulty


    def is_valid(digest):
        bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
        return bits[:difficulty] == zeros


    i = 0
    while True:
        i += 1
        s = prefix + str(i)
        if is_valid(hashlib.sha256(s.encode()).digest()):
            p.sendline(str(i))
            break
else:
    set_verbosity(5)
    bytecode = open(localfile, 'rb').read()
    bytecode = bytearray.fromhex(bytecode.decode())

for _ in range(10):
    if localfile is None:
        p.recvuntil('Challenge')
        print(p.readline())
        bytecode_hex = p.readline().decode().strip()
        print(bytecode_hex)
        bytecode = bytearray.fromhex(bytecode_hex)
        p.recvuntil('your tx data:')
    m = ManticoreEVM()
    user_account = m.create_account(balance=1000)
    print(f'user address: {int(user_account)}')
    contract_account = m.create_contract(owner=user_account, init=bytecode)
    print(f'contract address: {int(user_account)}')
    print(f'init killed: {m.count_killed_states()}')
    print(f'init terminated: {m.count_terminated_states()}')
    print(f'init busy: {m.count_busy_states()}')
    print(f'init ready: {m.count_ready_states()}')
    for state in m.ready_states:
        world = state.platform
        bytecode = world.get_code(contract_account)
        bytecode, = state.concretize(bytecode, 'ONE')
        for instr in evm.EVMAsm.disassemble_all(bytecode):
            print(f'0x{instr.pc:x} {instr}')

    symbolic_data = m.make_symbolic_buffer(320, name='symbolic_data')
    symbolic_value = m.make_symbolic_value(name='symbolic_value')
    tx_address = m.transaction(
        caller=user_account,
        address=contract_account,
        data=symbolic_data,
        value=symbolic_value,
    )
    print(f'tx address: {tx_address}')
    print(f'tx killed: {m.count_killed_states()}')
    print(f'tx terminated: {m.count_terminated_states()}')
    print(f'tx busy: {m.count_busy_states()}')
    print(f'tx ready: {m.count_ready_states()}')

    for i, state in enumerate(m.ready_states):
        print(f'### TRACE {i} ###')
        for _, pc, _, instr in state.context['evm.trace']:
            print(f'0x{pc:x} {instr}')
        print(f'### STORAGE {i} ###')
        ok = False
        for sindex, svalue in state.platform.get_storage_items(contract_account):
            sindex, = state.concretize(sindex, "ONE")
            svalue, = state.concretize(svalue, "ONE")
            if sindex == 0:
                ok = svalue == 1
                break
        if ok:
            print(f'### DATA {i} ###')
            data, = state.concretize(symbolic_data, "ONE")
            if localfile is None:
                p.sendline(data.hex())
            else:
                print(data.hex())
            break
    if localfile is not None:
        break
if localfile is None:
    p.interactive()
