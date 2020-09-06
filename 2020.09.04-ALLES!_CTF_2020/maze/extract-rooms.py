#!/usr/bin/env python3
from dataclasses import dataclass
import json
import re


@dataclass
class Room:
    id: int
    code: str = ''
    n_lines = 0


rooms = []
with open('maze.objdump') as fp:
    current_room = None
    for line in fp:
        if current_room is None:
            m = re.match(r'^[0-9a-f]{16} <room(\d+)>:', line)
            if m is not None:
                current_room = Room(int(m.group(1)))
        elif line == '\n':
            if False:
                with open(f'rooms/room{current_room.id}', 'w') as fp2:
                    fp2.write(current_room.code)
            rcx, = re.findall(r'mov    \$0x(.*),%rcx', current_room.code)
            rcx = int(rcx, 16)
            rooms.append((current_room.id, rcx))
            current_room = None
        else:
            code = line[32:]
            code = re.sub(r'0x[0-9a-f]+\(%rip\)', '?(%rip)', code)
            if len(code) > 0:
                current_room.code += code
                current_room.n_lines += 1
rooms.sort()
with open('rooms.json', 'w') as fp:
    json.dump(rooms, fp, indent=4)
with open('rooms.h', 'w') as fp:
    fp.write('const std::uint32_t rcxes[] = {')
    rcxes = []
    for i, (room_id, rcx) in enumerate(rooms):
        assert i == room_id
        rcxes.append(hex(rcx))
    fp.write(', '.join(rcxes))
    fp.write('};\n')
