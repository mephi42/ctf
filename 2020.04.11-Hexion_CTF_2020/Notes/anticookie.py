#!/usr/bin/env python3
import base64
import zlib
x = 'eJyrVsrLL0ktVrKKVqqoKCxU0lGKUTI0MnYcYKCuFFsLAKkTKJk=='
xx = base64.urlsafe_b64decode(x)
xxx = zlib.decompress(xx)
print(xxx.decode())
