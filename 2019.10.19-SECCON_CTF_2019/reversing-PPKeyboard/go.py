#!/usr/bin/env python3
from collections import defaultdict
import pyshark

mappings = {
}
capture = pyshark.FileCapture('packets.pcapng')
count = 0
freqs = defaultdict(int)
prev = None
word = ''
keyids = []
for packet in capture:
    if packet.usb.src != '1.7.4':
        continue
    capdata = packet.layers[1].usb_capdata
    if capdata.endswith(':00'):
        continue
    assert (capdata.endswith(':7f'))
    assert (capdata.startswith('09:'))
    keyid = capdata[3:-3]
    print(f'{len(keyids)} {keyid}')
    keyids.append(keyid)
    if keyid not in mappings:
        mappings[keyid] = chr(ord('A') + len(mappings))
        word += mappings[keyid]
    else:
        word += mappings[keyid]
    freqs[keyid] += 1
    count += 1
    prev = packet
lst = sorted(freqs.items(), key=lambda x: -x[1])
for key, freq in lst:
    print(f'{key} {freq * 100 / count}')
print(f'unique: {len(lst)}')
print(f'total: {count}')
print(f'{word}')

letters = ''
for i in range(0, len(keyids), 2):
    letters += chr(int(keyids[i][-1] + keyids[i + 1][-1], 16))
print(letters)
