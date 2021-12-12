#!/usr/bin/env python3
import z3


def step(state, j):
    d, e, f, g, h, i = state

    e += 1
    k = 2 ** 64

    def l(a, b):
        return ((a - j) * pow(256, b - 2, b)) % b

    f = l(f, k + 13)
    g = l(g, k + 37)
    h = l(h, k + 51)
    i = l(i, k + 81)

    return [d, e, f, g, h, i]


def main():
    state = [
        int(s, 36)
        for s in [
            "0",
            "0",
            "zeexaxq012eg",
            "k2htkr1olaj6",
            "3cbp5mnkzllt3",
            "2qpvamo605t7j",
        ]
    ]

    # sanity check
    assert step(state, ord("S")) == [
        0,
        1,
        15510583740208053765,
        7864596329631544740,
        11879310176453485125,
        17632808840894717256,
    ]

    solver = z3.Solver()
    flag = [z3.BitVec(f"flag[{i}]", 128) for i in range(32)]
    solver.add(flag[0] == ord("S"))
    solver.add(flag[1] == ord("E"))
    solver.add(flag[2] == ord("C"))
    solver.add(flag[3] == ord("C"))
    solver.add(flag[4] == ord("O"))
    solver.add(flag[5] == ord("N"))
    solver.add(flag[6] == ord("{"))
    for i in range(7, 31):
        solver.add(flag[i] >= 0x20)
        solver.add(flag[i] <= 0x7E)
    solver.add(flag[31] == ord("}"))
    for j in flag:
        state = step(state, j)
    d, e, f, g, h, i = state
    solver.add(d == 0)
    solver.add(e == 32)
    solver.add(f + g + h + i == 0)
    assert str(solver.check()) == "sat"
    model = solver.model()
    print(bytes(model[x].as_long() for x in flag))
    # z3 doesn't work
    # @winger: sum(256^i*s_i) == init_k (mod p_k)
    # SECCON{L3t5_wr1t3_y0ur_Qu1n3!!!}


if __name__ == "__main__":
    main()
