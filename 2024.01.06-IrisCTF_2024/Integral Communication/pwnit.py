#!/usr/bin/env python3
import json

from pwn import *


def connect():
    return remote("integral-communication.chal.irisc.tf", 10103)


def main():
    with connect() as tube:
        tube.sendlineafter(b"> ", b"1")
        message = "A" * 5
        payload = {"from": "guest", "act": "echo", "msg": message}
        payload = json.dumps(payload).encode()
        block_size = 16
        assert len(payload) == block_size * 3
        target_payload = {"from": "admin", "act": "flag", "msg": message}
        target_payload = json.dumps(target_payload).encode()
        assert len(target_payload) == block_size * 3
        tube.sendlineafter(b"Please enter your message: ", message.encode())
        tube.recvuntil(b"IV: ")
        iv = bytearray.fromhex(tube.recvline().decode())
        tube.recvuntil(b"Command: ")
        enc_payload = bytearray.fromhex(tube.recvline().decode())

        # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)

        # Forge the 2nd block.
        assert payload[block_size * 2 :] == target_payload[block_size * 2 :]
        for i, (x, y) in enumerate(
            zip(
                payload[block_size : block_size * 2],
                target_payload[block_size : block_size * 2],
            )
        ):
            enc_payload[i] ^= x ^ y
        tube.sendlineafter(b"> ", b"2")
        tube.sendlineafter(b"IV: ", iv.hex().encode())
        tube.sendlineafter(b"Command: ", enc_payload.hex().encode())

        # Bug: the challenge shows us the mangled result.
        tube.recvuntil(b"Failed to decode UTF-8: ")
        mangled = bytes.fromhex(tube.recvline().decode())
        assert mangled[block_size:] == target_payload[block_size:]

        # Forge the 1st block.
        for i, (x, y) in enumerate(
            zip(
                mangled[:block_size],
                target_payload[:block_size],
            )
        ):
            iv[i] ^= x ^ y
        tube.sendlineafter(b"> ", b"2")
        tube.sendlineafter(b"IV: ", iv.hex().encode())
        tube.sendlineafter(b"Command: ", enc_payload.hex().encode())

        # irisctf{cbc_d03s_n07_m34n_1n73gr1ty}

        tube.interactive()


if __name__ == "__main__":
    main()
