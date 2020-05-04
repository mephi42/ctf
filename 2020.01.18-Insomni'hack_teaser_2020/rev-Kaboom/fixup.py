#!/usr/bin/env python3
exe = bytearray(open('kaboom.exe', 'rb').read())
src = exe.index(b'\x5a\x57\x51\xab')
dst = exe.index(b'\xbb\x57\x51\xab')
len = 0x11a1
exe[dst:dst + len] = exe[src:src + len]
exe[src:src + len] = b'\x00' * len
open('kaboom_fixed.exe', 'wb').write(exe)
