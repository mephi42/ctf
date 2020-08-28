from math import sqrt

import numpy as np
from pwn import *
from scipy.linalg import svd

catalog = []
with open('test.txt') as fp:
    for line in fp:
        if line == '\n':
            continue
        x, y, z, m = line.split(',')
        catalog.append((float(x), float(y), float(z)))

io = remote('attitude.satellitesabove.me', 5012)
io.recvuntil('Ticket please:')
io.sendline('ticket{yankee74123papa:GEZYBOSlNoCCvlye-dEhkx335audPkanSlFPk4nrRwFGW5ONV6HAsWwMCo5zMzTXww}')
while True:
    io.recvuntil('--------------------------------------------------\n')
    w = []
    v = []
    while True:
        line = io.recvline().decode().strip()
        if line == '':
            break
        id, rest = line.split(':')
        x, y, z = rest.split(',')
        # w[k] is the k-th 3-vector measurement in the reference frame
        w.append(catalog[int(id)])  # no `- 1` here
        # v[k] is the corresponding k-th 3-vector measurement in the body frame
        v.append((float(x), float(y), float(z)))
    w = np.array(w)
    v = np.array(v)
    print(f'{w=}')
    print(f'{v=}')
    # Solution by Singular Value Decomposition
    # 1. Obtain a matrix B (how the hell should I have known this is supposed to be
    # an outer product?!)
    b = np.zeros((3, 3))
    for wi, vi in zip(w, v):
        b += np.outer(wi, vi)
    print(f'{b=}')
    # 2. Find the singular value decomposition of B
    u, s, vh = svd(b)
    print(f'{u=}')
    print(f'{s=}')
    print(f'{vh=}')
    print(f'{u @ np.diag(s) @ vh=}')
    # The rotation R in the problem's definition transforms the body frame to the
    # reference frame.
    # 3. The rotation matrix is simply:
    m = np.diag([1., 1., np.linalg.det(u) * np.linalg.det(vh.T)])
    print(f'{m=}')
    r = u @ m @ vh
    print(f'{r=}')
    # sanity check
    for i, (wi, vi) in enumerate(zip(w, v)):
        print(f'{i} {wi} {r @ vi}')
    # convert rotation matrix to quaternion
    qw = math.sqrt(1. + r[0][0] + r[1][1] + r[2][2]) / 2.
    qx = (r[2][1] - r[1][2]) / (4. * qw)
    qy = (r[0][2] - r[2][0]) / (4. * qw)
    qz = (r[1][0] - r[0][1]) / (4. * qw)
    # send solution
    io.sendline(f'{qx},{qy},{qz},{qw}')
# flag{yankee74123papa:GKU3FQihHBs1IREZrBDoQQ1y3xWeYpDQkE-XhVPSf23m3R9pQqF-YRFdz-Q0xQarE-wtpuxwnWrqXAzrI9r1rUI}
