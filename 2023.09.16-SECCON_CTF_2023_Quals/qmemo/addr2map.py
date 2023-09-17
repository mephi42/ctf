#!/usr/bin/env python3
import sys
def main():
    pid, = sys.argv[1:]
    pid = int(pid)
    maps = []
    with open(f"/proc/{pid}/maps") as fp:
        for line in fp:
            range, flags, offset, dev, inode, *rest = line.strip().split(maxsplit=5)
            if len(rest) == 0:
                path = None
            else:
                assert len(rest) == 1
                path, = rest
            start, end = range.split("-")
            start = int(start, 16)
            end = int(end, 16)
            offset = int(offset, 16)
            inode = int(inode)
            maps.append((start, end, flags, offset, dev, inode, path))
    for addr in sys.stdin:
        addr = int(addr, 0)
        for start, end, flags, offset, dev, inode, path in maps:
            if start <= addr < end:
                if path is None:
                    path = f"0x{start:x}[{flags}]"
                    addend = 0
                else:
                    addend = offset
                print(f"0x{addr:x} {path}+0x{addr - start + addend}")
                break
        else:
            print(hex(addr))


if __name__ == "__main__":
    main()
