#!/usr/bin/env python3
from hashlib import sha256

pass2 = bytes.fromhex('26662f4d3d464c262f79775a5e242a6b3d242d595157475b5058597c3c2a2b7a357d782f5c28695338336b342433544b6922214a757700fff7ff7f00000000000000000000a0f5f9f7ff7f000080e1fff7ff7f00000000000001000000e8e4fff7ff7f00')
enc = open('flag.enc', 'rb').read()
mask = sha256(pass2).digest()
assert len(mask) == len(enc)
print(b''.join(bytes((a ^ b,)) for a, b in zip(mask, enc)))

# pbctf{I_hate_c0re_dumps_now_:(}
