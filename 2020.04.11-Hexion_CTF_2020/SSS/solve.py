from sage.all import *

data = []
with open('data.txt') as fp:
    for s in fp:
        x, r = s.split()
        data.append((int(x), int(r)))
modulus = 2 ** 521 - 1
ring = GF(modulus)
a = []
y = []
for x, r in data:
    row = []
    for p in range(100, -1, -1):
        row.append(pow(x, p, modulus))
    a.append(row)
    y.append([r])
a = Matrix(a, ring=ring)
y = Matrix(y, ring=ring)
print(a.solve_right(y))
