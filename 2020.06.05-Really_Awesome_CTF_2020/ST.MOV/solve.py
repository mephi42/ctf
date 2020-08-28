#!/usr/bin/env python3
import itertools
import numpy as np
from scipy.io import wavfile

hz, wav = wavfile.read('challenge.wav')
bit_size_sec = 0.5
bit_size_samples = int(bit_size_sec * hz)
std_threshold = 7000
ch0 = wav[:, 0]
bits = ''
for i in range(0, len(ch0), bit_size_samples):
    std = np.std(ch0[i:i + bit_size_samples])
    bits += '1' if std < std_threshold else '0'
bits = bits[:-1]
print(bits)
bits = bits.replace('100000', '')  # these are spaces, FFS
s = ''
for i in range(0, len(bits), 7):
    chunk = bits[i:i + 7]
    if chunk == '':
        continue
    ch = chr(int(chunk, 2))
    print(f'{i} {i * bit_size_sec} {chunk} {ch}')
    s += ch
print(s)
