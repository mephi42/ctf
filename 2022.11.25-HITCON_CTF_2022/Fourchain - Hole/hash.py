import z3


def ComputeUnseededHash(key):
    hash = key & 0xffffffff
    hash = ~hash + (hash << 15)
    hash = hash ^ z3.LShR(hash, 12)
    hash = hash + (hash << 2)
    hash = hash ^ z3.LShR(hash, 4)
    hash = hash * 2057
    hash = hash ^ z3.LShR(hash, 16)
    return hash & 0x3fffffff


if __name__ == "__main__":
    assert z3.simplify(ComputeUnseededHash(z3.BitVecVal(1, 32))) == 0x12d60bf6
    keys = []
    for h in range(0x100):
        s = z3.Solver()
        i = z3.BitVec("i", 32)
        s.add(h == ComputeUnseededHash(i))
        assert str(s.check()) == "sat"
        keys.append(s.model()[i].as_long())
    print(keys)