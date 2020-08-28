#!/usr/bin/env python3
from collections import deque
from dataclasses import dataclass
import json
import struct
import sys

import networkx
from networkx.drawing.nx_agraph import write_dot

WORKER_NAMES = {
    0: 'main',
    1: 'loader',
    2: 'fs',
    3: 'vm',
    4: 'printf',
    5: 'last',
}
NEXT_WORKER = {
    1: 2,
    2: 3,
    3: 4,
    4: 5,
    5: 1,
}
PERM = [2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 2, 2, 1, 2, 1, 2, 1, 2, 1]


def parse_0(entry):
    data = bytes.fromhex(entry['data'])
    pc, = struct.unpack('<I', data[0x0:0x4])
    entry['pc'] = pc
    r0, r1 = struct.unpack('<QQ', data[0x8:0x18])
    entry['r0'], entry['r1'] = r0, r1
    pc_2, = struct.unpack('<I', data[0x18:0x1c])
    entry['pc_2'] = pc_2
    r0_2, r1_2 = struct.unpack('<QQ', data[0x20:0x30])
    entry['r0_2'], entry['r1_2'] = r0_2, r1_2


def parse_1(entry):
    data = bytes.fromhex(entry['data'])
    arg3, next_pc, forked_pc, pc, is_forked = struct.unpack('<QIIIB', data[0x18:0x2d])
    entry['arg3'], entry['next_pc'], entry['forked_pc'], entry['pc'], entry['is_forked'] = arg3, next_pc, forked_pc, pc, is_forked
    arg1, arg2, opcode = struct.unpack('<QQH', data[0x0:0x12])
    entry['arg1'], entry['arg2'], entry['opcode'] = arg1, arg2, opcode


def strip0(str_bytes):
    nul_pos = str_bytes.find(b'\0')
    if nul_pos != -1:
        str_bytes = str_bytes[:nul_pos]
    return str_bytes


def parse_2(entry):
    data = bytes.fromhex(entry['data'])
    pc, = struct.unpack('<I', data[0x0:0x4])
    entry['pc'] = pc
    if pc == 0xffffffe0:
        entry['str'] = strip0(data[0x8:0x10]).decode()
    entry['r0'], entry['r1'] = struct.unpack('<QQ', data[0x8:])


def parse_hash(data):
    result = []
    for i in range(0, len(data), 20):
        pc, r0, r1 = struct.unpack('<IQQ', data[i:i + 20])
        result.append({"pc": pc, "r0": r0, "r1": r1})
    return result


def read_enries(trace):
    with open(trace) as fp:
        for line in fp:
            entry = json.loads(line)
            op = entry.get('op')
            if ((entry['worker'] == 5 and op == 'send') or
                    (entry['worker'] == 1 and op == 'recv')):
                parse_0(entry)
            elif ((entry['worker'] in (1, 2) and op == 'send') or
                  (entry['worker'] in (2, 3) and op == 'recv')):
                parse_1(entry)
            elif ((entry['worker'] in (3, 4) and op == 'send') or
                  entry['worker'] in (4, 5) and op == 'recv'):
                parse_2(entry)
            if op == 'hash':
                entry['hash'] = parse_hash(bytes.fromhex(entry['data']))
            yield entry


class Worker:
    last_recved_thread_id = 0
    n_sent_since_last_recv = 0

    def __init__(self, name):
        self.name = name
        self.inbox = deque()


@dataclass
class Module:
    name: str
    start: int
    size: int


class Modules:
    def __init__(self):
        self.last_opened_path = {}
        self.brk = 0
        self.modules = []

    def handle_entry(self, entry):
        worker = entry['worker']
        op = entry.get('op')
        if op == 'open':
            self.last_opened_path[worker] = bytes.fromhex(entry['path']).decode()
        elif op == 'load':
            size = entry['size'] - self.brk
            module = Module(self.last_opened_path[worker], (self.brk // 40) * 0x10, (size // 40) * 0x10)
            entry['start_pc'] = module.start
            entry['end_pc'] = module.start + module.size
            self.modules.append(module)
            self.brk = entry['size']

    def resolve_pc(self, pc):
        for module in self.modules:
            if module.start <= pc < module.start + module.size:
                return f'{module.name} + 0x{pc - module.start:x}'
        if pc in (0xffffffb0, 0xffffffe0, 0xfffffff0):
            return hex(pc)
        raise Exception(f'wtf: 0x{pc:x}')

    def resolve_entry_pcs(self, entry):
        for key in 'pc', 'next_pc':
            if key in entry:
                entry[key] = self.resolve_pc(entry[key])


def main():
    entries = read_enries(sys.argv[1])
    workers = [Worker(WORKER_NAMES[i]) for i in range(6)]
    next_thread_id = 1
    thread_pcs = {}
    cfg = networkx.DiGraph()
    modules = Modules()
    for entry in entries:
        orig_entry = entry
        entry = entry.copy()
        worker = workers[entry['worker']]
        old_thread_pc = None
        op = entry.get('op')
        if op == 'recv':
            if worker.n_sent_since_last_recv == 0:
                print(json.dumps({
                    'worker': WORKER_NAMES[entry['worker']],
                    'op': 'thread_exit',
                    'thread_id': worker.last_recved_thread_id,
                }))
            orig_sent_entry, worker.last_recved_thread_id = worker.inbox.popleft()
            assert orig_entry.get('data') == orig_sent_entry.get('data')
            worker.n_sent_since_last_recv = 0
            entry['thread_id'] = worker.last_recved_thread_id
        elif op == 'send':
            if worker.n_sent_since_last_recv == 0:
                entry['thread_id'] = worker.last_recved_thread_id
            else:
                old_thread_pc = thread_pcs.get(worker.last_recved_thread_id)
                entry['thread_id'] = next_thread_id
                print(json.dumps({
                    'worker': WORKER_NAMES[entry['worker']],
                    'op': 'thread_create',
                    'thread_id': next_thread_id,
                }))
                next_thread_id += 1
            worker.n_sent_since_last_recv += 1
            target_worker_id = NEXT_WORKER[entry['worker']]
            entry['target_worker'] = WORKER_NAMES[target_worker_id]
            target_worker = workers[target_worker_id]
            target_worker.inbox.append((orig_entry, entry['thread_id']))
        else:
            entry['thread_id'] = worker.last_recved_thread_id
        modules.handle_entry(entry)
        new_thread_pc = entry.get('pc')
        if new_thread_pc is not None:
            new_thread_pc &= ~0xf
            if old_thread_pc is None:
                old_thread_pc = thread_pcs.get(entry['thread_id'])
            if old_thread_pc is not None and old_thread_pc != new_thread_pc:
                old_thread_pc &= ~0xf
                node_src = modules.resolve_pc(old_thread_pc)
                node_dst = modules.resolve_pc(new_thread_pc)
                if not cfg.has_edge(node_src, node_dst):
                    cfg.add_edge(node_src, node_dst)
            thread_pcs[entry['thread_id']] = new_thread_pc
        try:
            del entry['data']
        except KeyError:
            pass
        entry['worker'] = WORKER_NAMES[entry['worker']]
        for key in 'opcode', 'arg1', 'arg2', 'arg3', 'r0', 'r1', 'start_pc', 'end_pc':
            if key in entry:
                entry[key] = hex(entry[key])
        modules.resolve_entry_pcs(entry)
        print(json.dumps(entry))
    write_dot(cfg, 'snoop.dot')


if __name__ == '__main__':
    main()
