#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return process([os.path.expanduser("~/.wasmtime/bin/wasmtime"), "sc2elf.wasm", "--dir", "./"])
    else:
        return remote("sc2elf.2021.ctfz.one", 31337)


def prompt(tube, choice):
    tube.sendlineafter("5. Exit", str(choice))


def set_shellcode(tube, shellcode):
    prompt(tube, 1)
    tube.sendline(base64.b16encode(shellcode))


def set_header(tube, header):
    prompt(tube, 2)
    tube.sendlineafter("Paste base16 encoded header:", base64.b16encode(header))


def get_result(tube):
    prompt(tube, 3)
    tube.recvuntil("Result: ")
    return bytes.fromhex(tube.recvline().decode())


def print_description(tube):
    prompt(tube, 4)


def exit(tube):
    prompt(tube, 5)


def main():
    with connect() as tube:
        set_shellcode(tube, b'S' * 240)
        set_header(tube, b'\x7fELF' + (b'H' * 80))
        with open('elf', 'wb') as fp:
            fp.write(get_result(tube))
        tube.interactive()


if __name__ == "__main__":
    main()
