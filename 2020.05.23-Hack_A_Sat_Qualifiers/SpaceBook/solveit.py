from math import sqrt

import numpy as np
from pwn import *
from scipy.linalg import svd

catalog = []
with open('test.txt') as fp:
    for line in fp:
        if line == '\n':
            continue
        x, y, z, m = line.split(',')
        catalog.append((float(x), float(y), float(z), float(m)))

io = remote('spacebook.satellitesabove.me', 5015)
io.recvuntil('Ticket please:\n')
io.sendline('ticket{quebec3787yankee:GOESoZKE7JTlhU8ldrrsI_Ly9GNgFtOimtdDoYeUHkP7Lvl16RFCL5OcY1n0Ioq5Gg}')
for _ in range(5):
    indices = []
    while True:
        line = io.recvline()
        if line == b'\n':
            break
        x, y, z, m = line.split(b',')
        m = float(m)
        for ii, (_, _, _, mm) in enumerate(catalog):
            if abs(m - mm) < 0.00001:
                indices.append(ii)
                break
        else:
            raise Exception('Not found')
    io.recvuntil(b'Index Guesses (Comma Delimited):\n')
    io.sendline(','.join(map(str, indices)))
    assert io.recvline().endswith(b'Left...\n')
io.interactive()
# flag{quebec3787yankee:GNF1s2HxfqZSXKEzQmRdnddfi_PJAeJmUU3W0jGGDMrvMKh73L48Mwt_3Q9qg0fDgfubjc3JKgzkLfT6DJVYgTg}
