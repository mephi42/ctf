from collections import deque
import os
import struct
import sys

import z3

from snoop import NEXT_WORKER, PERM, read_enries, strip0, WORKER_NAMES

FILL_ME = object()


def as_signed64(x):
    if isinstance(x, int) and (x & 0x8000000000000000):
        x -= 0x10000000000000000
    return x


def ite(x, y, z):
    if x is True:
        return y
    if x is False:
        return z
    x = z3.simplify(x)
    if z3.is_true(x):
        return y
    if z3.is_false(x):
        return z
    return z3.If(x, y, z)


def z3_binop64(f, x, y):
    if isinstance(x, int) and isinstance(y, int):
        return f(x, y)
    if isinstance(x, int):
        x = z3.BitVecVal(x, 64)
    if isinstance(y, int):
        y = z3.BitVecVal(y, 64)
    return f(x, y)


def fmt(entry):
    entry2 = {}
    for k, v in entry.items():
        if not isinstance(v, int) and not isinstance(v, str):
            v = '...'
        entry2[k] = v
    return str(entry2)


class WorkerState:
    def __init__(self, index, state):
        self.index = index
        self.inbox = deque()
        self.outbox = deque()
        self.hash = {}  # (pc >> 4, r1) -> (pc, r0, r1)
        self.state = state
        self.recv_cond = True

    def __str__(self):
        return WORKER_NAMES[self.index]

    def outbox_append(self, message):
        print('OUTBOX(S):  ' + fmt(message))
        self.outbox.append(message)

    def fixup(self, symbolic_entry, concrete_entry):
        for k in symbolic_entry.keys() | concrete_entry.keys():
            if k in ('data', 'str', 'insn', 'cond'):
                continue
            symbolic_value = symbolic_entry.get(k)
            concrete_value = concrete_entry.get(k)
            if symbolic_value is FILL_ME:
                assert concrete_value is not None, k
                symbolic_entry[k] = concrete_value
            else:
                if isinstance(symbolic_value, z3.Z3PPObject):
                    pass
                else:
                    assert symbolic_value == concrete_value, (k, symbolic_value, concrete_value)

    def handle_recv(self, concrete_entry):
        print('INBOX(C):   ' + fmt(concrete_entry))
        assert len(self.outbox) == 0
        symbolic_entry = self.inbox.popleft()
        print('INBOX(S):   ' + fmt(symbolic_entry))
        self.fixup(symbolic_entry, concrete_entry)
        symbolic_pc = symbolic_entry.get('pc')
        if symbolic_pc is not None and not isinstance(symbolic_pc, int):
            # concretize
            concrete_pc = concrete_entry['pc']
            symbolic_entry['pc'] = concrete_pc
            current_cond = symbolic_entry['cond']
            # try to flip it
            self.state.solver.push()
            try:
                self.state.solver.add(current_cond)
                self.state.solver.add(symbolic_pc != concrete_pc)
                sat = self.state.solver.check()
                if str(sat) == 'sat':
                    model = self.state.solver.model()
                    s = bytearray()
                    for ch_var in self.state.chars_read:
                        ch_val = model[ch_var].as_signed_long()
                        if ch_val == -1:
                            break
                        s.append(ch_val)
                    s = s.hex()
                    print('FLIP:       ' + s)
                    os.makedirs(os.path.join('corpus', s), exist_ok=True)
            finally:
                self.state.solver.pop()
            symbolic_entry['cond'] = z3.And(current_cond, symbolic_pc == concrete_pc)
        self.recv_cond = symbolic_entry['cond']
        if self.index == 1:
            insn = bytes.fromhex(concrete_entry['insn'])
            opcode, = struct.unpack('<I', insn[0x0:0x4])
            if opcode == 0x1d:
                # image init
                pass
            else:
                last_qw, = struct.unpack('<Q', insn[0x20:0x28])
                if last_qw == 1:
                    arg2, = struct.unpack('<Q', insn[0x10:0x18])
                elif last_qw == 0:
                    perm = PERM[opcode]
                    if perm == 1:
                        arg2, = struct.unpack('<Q', insn[0x10:0x18])
                    elif perm == 2:
                        arg2 = symbolic_entry['r0_2']
                    else:
                        assert False, perm
                else:
                    assert False, last_qw
                self.outbox_append({
                    'worker': self.index,
                    'op': 'send',
                    'arg1': symbolic_entry['r0'],
                    'arg2': arg2,
                    'opcode': FILL_ME,
                    'pc': symbolic_entry['pc'] & 0xfffffff0,
                    'arg3': symbolic_entry['r1'],
                    'next_pc': FILL_ME,
                    'forked_pc': FILL_ME,
                    'is_forked': FILL_ME,
                    'cond': symbolic_entry['cond'],
                })
        elif self.index == 2:
            opcode = symbolic_entry['opcode']
            if opcode == 0x16:
                assert False, 'open'
            elif opcode == 0x17:
                # getc
                ch_var = z3.BitVec('getc' + str(len(self.state.chars_read)), 64)
                self.state.solver.add(z3.And(ch_var >= -1, ch_var <= 255))
                self.state.chars_read.append(ch_var)
                self.outbox_append({
                    **symbolic_entry,
                    'worker': self.index,
                    'op': 'send',
                    'opcode': 5,
                    'arg1': ch_var,
                })
            elif opcode == 0x18:
                assert False, 'putc'
            elif opcode == 0x19:
                assert False, 'close'
            elif opcode == 0x1c:
                print('EXIT')
                sys.exit(0)
            elif opcode == 0x1f:
                assert False, 'splice'
            elif opcode == 0x20:
                assert False, 'unlink'
            elif opcode == 0x21:
                assert False, 'lseek'
            else:
                self.outbox_append({
                    **symbolic_entry,
                    'worker': self.index,
                    'op': 'send',
                })
        elif self.index == 3:
            opcode = symbolic_entry['opcode']
            mainline_msg = {
                'worker': self.index,
                'op': 'send',
                'pc': symbolic_entry['next_pc'],
                'r0': symbolic_entry['arg1'],
                'r1': symbolic_entry['arg3'],
                'cond': symbolic_entry['cond'],
            }
            is_forked = symbolic_entry['is_forked']
            forked_r0 = None
            if opcode == 0x0:
                # add
                mainline_msg['r0'] = symbolic_entry['arg1'] + symbolic_entry['arg2']
            elif opcode == 0x1:
                # sub
                mainline_msg['r0'] = (symbolic_entry['arg1'] - symbolic_entry['arg2']) & 0xffffffffffffffff
            elif opcode == 0x2:
                # jnz
                is_forked = 0
                mainline_msg['pc'] = ite(symbolic_entry['arg2'] == 0, symbolic_entry['forked_pc'], mainline_msg['pc'])
            elif opcode == 0x3:
                # cmplt
                mainline_msg['r0'] = ite(as_signed64(symbolic_entry['arg1']) < as_signed64(symbolic_entry['arg2']), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0x4:
                # cmpeq
                mainline_msg['r0'] = ite(symbolic_entry['arg1'] == symbolic_entry['arg2'], z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0x5 or opcode == 0x7:
                # nop
                pass
            elif opcode == 0x6:
                assert False, 'cmpz'
            elif opcode == 0x8:
                # hirandom
                forked_r0 = symbolic_entry['arg3']
                mainline_msg['r0'] = FILL_ME
                is_forked = 1
            elif opcode == 0x9:
                # inc
                mainline_msg['r1'] = symbolic_entry['arg3'] + 1
            elif opcode == 0xa:
                # cmpgt
                mainline_msg['r0'] = ite(as_signed64(symbolic_entry['arg1']) > as_signed64(symbolic_entry['arg2']), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0xb:
                mainline_msg['r1'] = (symbolic_entry['arg3'] & 0xffffffff00000000) | (symbolic_entry['arg2'] & 0xffffffff)
            elif opcode == 0xc:
                # mov
                mainline_msg['r0'] = symbolic_entry['arg2']
                mainline_msg['r1'] = symbolic_entry['arg1']
            elif opcode == 0xd:
                # jmp
                mainline_msg['pc'] = symbolic_entry['arg2']
                is_forked = 0
            elif opcode == 0xe:
                # mov
                mainline_msg['r0'] = symbolic_entry['arg3']
            elif opcode == 0xf:
                # mul
                mainline_msg['r0'] = symbolic_entry['arg1'] * symbolic_entry['arg2']
            elif opcode == 0x10:
                # xor
                mainline_msg['r0'] = symbolic_entry['arg1'] ^ symbolic_entry['arg2']
            elif opcode == 0x11:
                # and
                mainline_msg['r0'] = symbolic_entry['arg1'] & symbolic_entry['arg2']
            elif opcode == 0x12:
                # or
                mainline_msg['r0'] = z3_binop64(lambda x, y: x | y, symbolic_entry['arg1'], symbolic_entry['arg2'])
            elif opcode == 0x13:
                # shl
                mainline_msg['r0'] = symbolic_entry['arg1'] << (symbolic_entry['arg2'] % 64)
            elif opcode == 0x14:
                # shr
                mainline_msg['r0'] = symbolic_entry['arg1'] >> (symbolic_entry['arg2'] % 64)
            elif opcode == 0x15:
                # cmpne
                mainline_msg['r0'] = ite(symbolic_entry['arg1'] != symbolic_entry['arg2'], z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0x1a:
                # cmpge
                mainline_msg['r0'] = ite(as_signed64(symbolic_entry['arg1']) >= as_signed64(symbolic_entry['arg2']), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0x1b:
                # cmple
                mainline_msg['r0'] = ite(as_signed64(symbolic_entry['arg1']) <= as_signed64(symbolic_entry['arg2']), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            elif opcode == 0x1c:
                assert False, 'exit'
            elif opcode == 0x22:
                # lorandom
                random_var = z3.BitVec('random' + fmt(self.state.chars_read), 64)
                time_var = z3.BitVec('time' + fmt(self.state.chars_read), 64)
                self.state.chars_read += 1
                mainline_msg['r0'] = symbolic_entry['arg3'] ^ random_var ^ time_var
            else:
                assert False, 'setz'
            self.outbox_append(mainline_msg)
            if is_forked:
                self.outbox_append({
                    'worker': self.index,
                    'op': 'send',
                    'pc': symbolic_entry['forked_pc'],
                    'r0': mainline_msg['r0'] if forked_r0 is None else forked_r0,
                    'r1': mainline_msg['r1'],
                    'cond': symbolic_entry['cond'],
                })
        elif self.index == 4:
            pc = symbolic_entry['pc']
            if pc == 0xffffffb0 or pc == 0xffffffc0:
                # done
                pass
            elif pc == 0xffffffe0:
                str_bytes = strip0(struct.pack('<Q', symbolic_entry['r0']))
                print('printf("%s", ' + repr(str_bytes.decode()) + ')')
            elif pc == 0xfffffff0:
                print('printf("%ld", ' + repr(symbolic_entry['r0']) + ')')
            else:
                self.outbox_append({
                    **symbolic_entry,
                    'worker': self.index,
                    'op': 'send',
                })
        elif self.index == 5:
            pc = symbolic_entry['pc']
            if pc & 1:
                assert (pc & 3) == 1
                hash_key = pc >> 4, symbolic_entry['r1']
                hash_val = self.hash.get(hash_key)
                if hash_val is None:
                    self.hash[hash_key] = pc, symbolic_entry['r0'], symbolic_entry['r1']
                elif pc & 8:
                    self.outbox_append({
                        'worker': self.index,
                        'op': 'send',
                        'pc': hash_val[0],
                        'r0': hash_val[1],
                        'r1': hash_val[2],
                        'pc_2': symbolic_entry['pc'],
                        'r0_2': symbolic_entry['r0'],
                        'r1_2': symbolic_entry['r1'],
                        'cond': symbolic_entry['cond'],
                    })
                else:
                    self.outbox_append({
                        'worker': self.index,
                        'op': 'send',
                        'pc': symbolic_entry['pc'],
                        'r0': symbolic_entry['r0'],
                        'r1': symbolic_entry['r1'],
                        'pc_2': hash_val[0],
                        'r0_2': hash_val[1],
                        'r1_2': hash_val[2],
                        'cond': symbolic_entry['cond'],
                    })
            else:
                self.outbox_append({
                    **symbolic_entry,
                    'worker': self.index,
                    'op': 'send',
                    'pc_2': FILL_ME,  # uninitialized
                    'r0_2': FILL_ME,  # uninitialized
                    'r1_2': FILL_ME,  # uninitialized
                })
        else:
            assert False, self.index

    def handle_send(self, concrete_entry):
        if self.index == 1 and len(self.outbox) == 0:
            return {
                **concrete_entry,
                'cond': self.recv_cond,
            }
        print('SENDING(C): ' + fmt(concrete_entry))
        symbolic_entry = self.outbox.popleft()
        print('SENDING(S): ' + fmt(symbolic_entry))
        self.fixup(symbolic_entry, concrete_entry)
        return symbolic_entry


class State:
    def __init__(self):
        self.solver = z3.Solver()
        self.chars_read = []
        self.workers = [WorkerState(i, self) for i in range(6)]


def main():
    state = State()
    for entry in read_enries(sys.argv[1]):
        worker_id = entry['worker']
        worker = state.workers[worker_id]
        op = entry.get('op')
        if op == 'recv':
            worker.handle_recv(entry)
        elif op == 'send':
            target_worker = state.workers[NEXT_WORKER[worker_id]]
            target_worker.inbox.append({
                **worker.handle_send(entry),
                'worker': target_worker.index,
                'op': 'recv',
            })


if __name__ == '__main__':
    main()
