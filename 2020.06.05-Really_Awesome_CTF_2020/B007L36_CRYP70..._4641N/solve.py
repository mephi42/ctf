#!/usr/bin/env python3
import base64

# k=0x63 + p=0xbf -> 0x122 -> 0x00
# k=0x20 + p=0x82 ->  0xa2 -> 0x7f
# k=0x20 + p=0x83 ->  0xa3 -> 0xc2 0x80
# k=0x20 + p=0xc2 ->  0xe2 -> 0xc2 0xbf
# k=0x20 + p=0xc3 ->  0xe3 -> 0xc3 0x80
# k=0x63 + p=0xbe -> 0x121 -> 0xc3 0xbe

mapping = {}
with open('mapping.txt', 'r') as fp:
    for l in fp:
        x, y, z = l.split()
        k = bytes.fromhex(z)
        v = (int(x) + int(y)) % 290
        if k in mapping and mapping[k] != v:
            print(k)
        mapping[k] = v


def unescape(c):
    arr = []
    i = 0
    while i < len(c):
        for x, y in mapping.items():
            if c[i:i+len(x)] == x:
                arr.append(y)
                i += len(x)
                break
        else:
            assert False, c[i:].hex()
    return arr


plaintext = open('encryption_service/plaintext.txt', 'rb').read().strip()
print('p0: ' + plaintext.hex())
ciphertext = base64.b64decode(open('encryption_service/ciphertext.txt').read())
print('c0: ' + ciphertext.hex())
ciphertext = unescape(ciphertext)
print('c0: ' + str(ciphertext))
password = base64.b64decode(open('encryption_service/password.txt').read())
print('c1: ' + password.hex())
password = unescape(password)
print('c1: ' + str(password))
key = bytes(c - p for c, p in zip(ciphertext, plaintext))
print('k:  ' + key.hex())
assert bytes(c - k for c, k in zip(ciphertext, key)) == plaintext
flag = bytes(c - k for c, k in zip(password, key))
print('f:  ' + flag.hex())
print(flag)
