from collections import defaultdict
import numpy as np
from pwn import *

io = remote('stars.satellitesabove.me', 5013)
io.recvuntil('Ticket please:\n')
io.sendline('ticket{yankee30586november:GOP2uL2U9Ixa9v5iAlZhCt7-6ymyoQ9XE3Mqa_6qJHXyyTLV-e9uFJIB9OIH2BsTjw}')

for i in range(5):
    bright = []
    while True:
        line = io.recvline()
        if line == b'\n':
            break
        bright.append([int(dot) for dot in line.split(b',')])
    bright = np.array(bright, dtype=int)
    np.savetxt('bright.txt', bright, fmt='%3d')
    stars = np.zeros(bright.shape, dtype=int)
    stars_xy = defaultdict(list)
    for y in range(bright.shape[0]):
        for x in range(bright.shape[1]):
            if bright[y][x] < 255:
                continue
            if x > 0 and stars[y][x - 1] != 0:
                stars[y][x] = stars[y][x - 1]
                stars_xy[stars[y][x]].append((x, y))
                continue
            if y > 0 and stars[y - 1][x] != 0:
                stars[y][x] = stars[y - 1][x]
                stars_xy[stars[y][x]].append((x, y))
                continue
            if x > 0 and y > 0 and stars[y - 1][x - 1] != 0:
                stars[y][x] = stars[y - 1][x - 1]
                stars_xy[stars[y][x]].append((x, y))
                continue
            if x < bright.shape[1] - 1 and y > 0 and stars[y - 1][x + 1] != 0:
                stars[y][x] = stars[y - 1][x + 1]
                stars_xy[stars[y][x]].append((x, y))
                continue
            stars[y][x] = len(stars_xy) + 1
            stars_xy[stars[y][x]].append((x, y))
    np.savetxt('stars.txt', stars, fmt='%3d')
    io.recvuntil(b'(Finish your list of answers with an empty line)\n')
    for xy in stars_xy.values():
        xs = sorted([x for x, _ in xy])
        ys = sorted([y for _, y in xy])
        x = xs[len(xs) // 2]
        y = ys[len(ys) // 2]
        io.sendline(f'{y},{x}')
    io.sendline()
    assert io.recvline().endswith(b' Left...\n')
io.interactive()
# flag{yankee30586november:GEunCkqetwdnBQxx88nviWkQ5mUtb8CMBwxFTuRP-JHDYH1iKdzxIaxSRTuvYuWPExfAQ3nGIPL9RaF5R_I4v6Y}
