#!/usr/bin/env python3
import itertools

from pwn import *
import z3


def read_row(tube):
    s = tube.recvline().decode()
    start = s.index('[')
    end = s.rindex(']')
    return re.split(r'\s*,\s*', s[start+1:end])


def set_row(solver, m, i, row):
    for j, x in enumerate(row):
        if x == '-1':
            solver.add(m[i][j] == -1)
        elif x == '1':
            solver.add(m[i][j] == 1)
        elif x == '\'?\'':
            solver.add(z3.Or(m[i][j] == -1, m[i][j] == 1))
        else:
            assert False, x


def fmt_row(row):
    return '[' + ', '.join([str(val) for val in row]) + ']'


def fmt_m(m):
    return '[' + ', '.join([fmt_row(row) for row in m]) + ']'


def read_m(tube):
    tube.recvuntil(b'| M =\n')
    solver = z3.Solver()
    row = read_row(tube)
    n = len(row)
    m = [[z3.Int(f'm{i}_{j}') for j in range(n)] for i in range(n)]
    set_row(solver, m, 0, row)
    for i in range(n - 1):
        set_row(solver, m, i, row)
        row = read_row(tube)
    set_row(solver, m, n - 1, row)
    return solver, m


def main():
    tube = remote('76.74.178.201', 8001)
    while True:
        solver, m = read_m(tube)
        n = len(m)
        for i in range(n):
            for j in range(n):
                lij = 0
                for k in range(n):
                    lij += m[i][k] * m[j][k]
                if i == j:
                    solver.add(lij == n)
                else:
                    solver.add(lij == 0)
        sat = solver.check()
        assert str(sat) == 'sat'
        model = solver.model()
        for i in range(n):
            for j in range(n):
                m[i][j] = model[m[i][j]]
        m_str = fmt_m(m)
        print(m_str)
        tube.sendline(hashlib.md5(m_str.encode()).hexdigest())
    tube.interactive()


if __name__ == '__main__':
    main()
