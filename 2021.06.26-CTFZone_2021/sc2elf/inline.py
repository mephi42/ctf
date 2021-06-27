#!/usr/bin/env python3
import re
import sys

DECL_RE = re.compile(r"\n +var ([a-z]+):[^ ]+ = (.+);")


def main():
    (path,) = sys.argv[1:]
    with open(path) as fp:
        src = fp.read()
    pos = 0
    while True:
        decl = DECL_RE.search(src, pos)
        if decl is None:
            break
        name, val = decl.groups()
        usages = list(re.finditer(r"\b" + re.escape(name) + r"\b", src))
        if len(usages) == 2:
            val = f"({val})"
            src = (
                src[: decl.start()]
                + src[decl.end() : usages[1].start()]
                + val
                + src[usages[1].end() :]
            )
            pos = (
                pos
                - (decl.end() - decl.start())
                - (usages[1].end() - usages[1].start())
                + len(val)
            )
        else:
            pos += 1
    with open(path, "w") as fp:
        fp.write(src)


if __name__ == "__main__":
    main()
