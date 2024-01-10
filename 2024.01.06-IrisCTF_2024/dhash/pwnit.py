#!/usr/bin/env python3
from Crypto.Random import get_random_bytes
from sage.all import *

from pwn import *


def connect():
    return remote("dhash.chal.irisc.tf", 10101)


def main():
    with connect() as tube:
        tube.recvuntil(b"MySeededHash(")
        n = int(tube.recvuntil(b", ")[:-2])
        e = int(tube.recvuntil(b")")[:-1])
        print(f"{n=}")
        print(f"{e=}")

        def hash_block(block):
            assert len(block) == 256
            data = int.from_bytes(block, "big")
            data = pow(data, e, n)
            return data.to_bytes(256, "big")

        block1 = get_random_bytes(256)
        print(f"{block1.hex()=}")
        hash1 = hash_block(block1)
        print(f"{hash1.hex()=}")
        block2 = get_random_bytes(256)
        print(f"{block2.hex()=}")
        hash2 = hash_block(block2)
        print(f"{hash2.hex()=}")
        hash3 = bytes(b1 ^ b2 for b1, b2 in zip(hash1, hash2))
        print(f"{hash3.hex()=}")
        hash3_val = int.from_bytes(hash3, "big")
        print(f"{hash3_val=}")
        block3_val = int(GF(n)(hash3_val).nth_root(e))
        print(f"{block3_val=}")
        assert pow(block3_val, e, n) == hash3_val
        block3 = block3_val.to_bytes(256, "big")
        print(f"{block3.hex()=}")
        hash3_again = hash_block(block3)
        print(f"{hash3_again.hex()=}")

        tube.sendlineafter(b"> ", (block1 + block2 + block3).hex().encode())
        tube.interactive()  # irisctf{no_order_factorization_no_problem}


if __name__ == "__main__":
    main()
