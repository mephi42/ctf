#!/usr/bin/env python3
import struct
import sys


def main():
    (bin_path,) = sys.argv[1:]
    with open(bin_path, "rb") as fp:
        bin = fp.read()
    bin = bin.ljust((len(bin) + 7) & ~7, b"\0")
    dq = struct.unpack("<" + "Q" * (len(bin) // 8), bin)
    print("dq " + ",".join(map(hex, dq)))


if __name__ == "__main__":
    main()
