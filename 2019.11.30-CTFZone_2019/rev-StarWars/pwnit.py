#!/usr/bin/env python3
from pwn import *
io = process(['wine64-development', 'StarWars.exe'])
moves = [
    (50, 10, 0), (50, 20, 0), (50, 30, 0),
    (50, 40, 0), (50, 50, 0), (50, 60, 0),
    (50, 70, 0), (50, 90, 11), (80, 225, 16),
    (100, 98, 0), (200, 123, 1), (200, 67, 10),
    (200, 111, 6), (400, 145, 13), (800, 214, 3),
    (800, 254, 2), (800, 77, 9), (800, 118, 15),
    (800, 205, 8), (800, 255, 14), (1000, 243, 12),
    (1000, 141, 5), (1000, 109, 4), (1000, 137, 7),
]
print([x[2] for x in moves])
move_index = 0
while True:
    line = io.recvline().decode().strip()
    print(line)
    if 'Please choose one of following:' in line:
        shields, attack, target = moves[move_index]
        io.sendline(str(target))
        move_index += 1
    elif 'You win the game, take your prize!' in line:
        io.interactive()
