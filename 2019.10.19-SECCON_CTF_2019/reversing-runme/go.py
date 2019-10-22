#!/usr/bin/env python3
import hashlib
import os

buf = b'\0' * 16
counter = 3
for i in range(0x8008):
    buf = b'\0\0\0\0' + buf[4:]
    m = hashlib.md5()
    m.update(buf)
    buf = m.digest()
    key = buf.hex()
    if i > 0x7ff8:
        rc = os.system(f'openssl aes-128-ecb -d -in encdata -out flag{counter}.txt -K {key} -nosalt')
        if rc == 0:
            print(f'{i:x} ok {key}')
            counter += 1
        else:
            print(f'{i:x} fail')
