#!/usr/bin/env python3
import json
import sys
import uuid

import requests


ip, = sys.argv[1:]
s = requests.Session()
url = f'http://{ip}:8080'
r = s.post(f'{url}/api/register', json={'login': str(uuid.uuid4()), 'password': str(uuid.uuid4())})
r.raise_for_status()
r = s.get(f'{url}/api/posts/user', params={'paginate[iterator]': 'ALL', 'paginate[limit]': 99999})
r.raise_for_status()
print(str(r.status_code), flush=True)
print(str(r.headers), flush=True)
print(r.content.decode(), flush=True)
