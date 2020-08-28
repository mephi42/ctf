import numpy as np
from pwn import *


def quat2eul(q):
    w, x, y, z = q
    return np.array([
        math.atan2(2 * (w * x + y * z), 1 - 2 * (x ** 2 + y ** 2)),
        math.asin(2 * (w * y - z * x)),
        math.atan2(2 * (w * z + x * y), 1 - 2 * (y ** 2 + z ** 2)),
    ])


def eul2quat(angles):
    cr = math.cos(angles[0] / 2)
    sr = math.sin(angles[0] / 2)
    cp = math.cos(angles[1] / 2)
    sp = math.sin(angles[1] / 2)
    cy = math.cos(angles[2] / 2)
    sy = math.sin(angles[2] / 2)
    return np.array([
        cy * cp * cr + sy * sp * sr,
        cy * cp * sr - sy * sp * cr,
        sy * cp * sr + cy * sp * cr,
        sy * cp * cr - cy * sp * sr,
    ])


if args.LOCAL:
    io = process(['octave', 'challenge.m'])
    assert io.recvline().startswith(b'OpenJDK')
    sep = ' '
else:
    io = remote('filter.satellitesabove.me', 5014)
    io.recvuntil('Ticket please:\n')
    io.sendline('ticket{juliet23638yankee:GA_Qc-RX8Iod2avTdoEN56Htw39LjPygdDjS3TYz00P008zMprcgNhXux9pGhgOP1A}')
    sep = ','
for i in range(2400):
    print(str(i))
    if args.LOCAL:
        assert io.recvline() == b'err\n'
        io.recvline()
        assert io.recvline() == b'goal\n'
        io.recvline()
    w, x, y, z = io.recvline().decode().split()
    actual_quat = np.array([float(w), float(x), float(y), float(z)])
    print(f'{actual_quat=}')
    actual_eul = quat2eul(actual_quat)
    print(f'{actual_eul=}')
    observed_eul = np.copy(actual_eul)
    observed_eul[0] += i / 1000. + (i % 10) * 0.03
    observed_eul[1] += i / 1000. + (i % 10) * 0.03
    observed_eul[2] += i / 1000. + (i % 10) * 0.03
    observed_quat = eul2quat(observed_eul)
    io.sendline(sep.join(map(str, observed_quat)))
# flag{juliet23638yankee:GIilDGB-F7_80ftgl2hoWChesUAGYXylOG56m0bQV7FB4pTnaImsWCM6KOhXXkTt7jaYag4kdpgPDa0tHHne3DY}