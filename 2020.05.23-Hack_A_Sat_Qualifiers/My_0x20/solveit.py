import numpy as np
from pwn import *

# parse catalog
catalog = []
with open('test.txt') as fp:
    for line in fp:
        if line == '\n':
            continue
        x, y, z, _ = line.split(',')
        catalog.append((float(x), float(y), float(z)))
catalog = np.array(catalog)
# sanity check: catalog must consist of unit vectors
for item in catalog:
    assert abs(np.linalg.norm(item) - 1.) < 1e-6
# compute angles between each pair of catalog entries
angles = np.arccos(catalog @ catalog.T)
# sanity check: NaNs should occur only on diagonal
nan_indices = np.argwhere(np.isnan(angles))
assert np.array_equal(nan_indices[:, 0], nan_indices[:, 1])
# sanity check: numpy-fu should produce the same results as straightforward code
for i in range(0, catalog.shape[0], 17):
    for j in range(0, catalog.shape[0], 23):
        if i == j:
            continue
        assert np.arccos(np.dot(catalog[i], catalog[j])) == angles[i, j]
# index angles
angles = np.array(angles.flatten())
assert np.arccos(np.dot(catalog[29], catalog[31])) == angles[29 * catalog.shape[0] + 31]
angle_indices = angles.argsort()


def bisect_catalog(angle):
    low = 0
    high = angles.shape[0]
    while high >= low:
        current = low + (high - low) // 2
        current_angle = angles[angle_indices[current]]
        if angle < current_angle:
            high = current - 1
        else:
            low = current + 1
    ijs = []
    for ij in angle_indices[max(0, low - 10):min(low + 10, angles.shape[0])]:
        ijs.append((ij // catalog.shape[0], ij % catalog.shape[0]))
    return ijs


io = remote('myspace.satellitesabove.me', 5016)
io.recvuntil('Ticket please:\n')
io.sendline('ticket{kilo72696juliet:GPL5N1VCpOhO3QgvXjtux5F5kCpkWuC9ygMIFdumHrhV1Hv__1QaClsCTW292HdfiQ}')
for _ in range(5):
    query = []
    while True:
        line = io.recvline()
        if line == b'\n':
            break
        x, y, z, _ = line.split(b',')
        query.append((float(x), float(y), float(z)))
    query = np.array(query)
    # sanity check: query must consist of unit vectors
    for item in catalog:
        assert abs(np.linalg.norm(item) - 1.) < 1e-6
    indices = []
    for j in range(3, query.shape[0]):
        angle0 = np.arccos(np.dot(query[0], query[j]))
        angle1 = np.arccos(np.dot(query[1], query[j]))
        angle2 = np.arccos(np.dot(query[2], query[j]))
        index, = (set(j0 for _, j0 in bisect_catalog(angle0))
                  .intersection(j1 for _, j1 in bisect_catalog(angle1))
                  .intersection(j2 for _, j2 in bisect_catalog(angle2)))
        indices.append(index)
    io.recvuntil(b'Index Guesses (Comma Delimited):\n')
    io.sendline(','.join(map(str, indices)))
    assert io.recvline().endswith(b'Left...\n')
io.interactive()
# flag{kilo72696juliet:GO9kinvUU2fZ8XcFvsYloSMECarFcvCbtqENlApjWdMqCK7DEOz3rXhv_moArfKEyKiza0-9qjm_59iu3YlDQ4Q}
