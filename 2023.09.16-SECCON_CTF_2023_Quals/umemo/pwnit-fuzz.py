#!/usr/bin/env python3
import random

from pwn import *


def connect():
    return remote("localhost", 6318)


def gen_int():
    result = ""
    if random.randint(0, 1) == 0:
        result += "-"
    for i in range(random.randint(1, 14 - len(result))):
        result += str(random.randint(0, 9))
    return int(result)


LOGIN_DELIM = b"buildroot login:"
MENU_DELIM = b"\n> "
UMEMO_DELIM = b"\nM> "
KMEMO_DELIM = b"\nS> "
RANGE_DELIM = b"Out of range"
OUTPUT_DELIM = b"Output: "
INPUT_DELIM = b"Input: "
LARGE_DELIM = b"Too large"
OFFSET_DELIM = b"Offset: "
LOGIN = b"ctf"
SIZE_DELIM = b"Size: "


def fuzz(tube, fp):
    def send(data):
        tube.send(data)
        fp.write(data)
        fp.flush()

    logged_in = False
    while True:
        delim = tube.recvuntil((LOGIN_DELIM, MENU_DELIM, UMEMO_DELIM, KMEMO_DELIM))
        if delim.endswith(LOGIN_DELIM):
            if logged_in:
                # Crash.
                return
            logged_in = True
            tube.sendline(LOGIN)
        elif delim.endswith(MENU_DELIM):
            choice = random.randint(1, 2)  # don't exit
            send(str(choice).encode() + b"\n")
        elif delim.endswith(UMEMO_DELIM):
            choice = random.randint(0, 2)
            send(str(choice).encode() + b"\n")
            if choice in (1, 2):
                tube.recvuntil(b"Index: ")
                send(str(gen_int()).encode() + b"\n")
                if choice == 1:
                    tube.recvuntil((RANGE_DELIM, OUTPUT_DELIM))
                else:
                    assert choice == 2
                    delim = tube.recvuntil((RANGE_DELIM, INPUT_DELIM))
                    if delim.endswith(RANGE_DELIM):
                        pass
                    else:
                        assert delim.endswith(INPUT_DELIM)
                        send(b"A" * random.randint(0, 0xFF) + b"\n")
        else:
            assert delim.endswith(KMEMO_DELIM)
            choice = random.randint(0, 2)
            send(str(choice).encode() + b"\n")
            if choice in (1, 2):
                tube.recvuntil(OFFSET_DELIM)
                send(str(gen_int()).encode() + b"\n")
                delim = tube.recvuntil((SIZE_DELIM, RANGE_DELIM))
                if delim.endswith(RANGE_DELIM):
                    continue
                size = gen_int()
                send(str(size).encode() + b"\n")
                if choice == 1:
                    tube.recvuntil((OUTPUT_DELIM, LARGE_DELIM))
                else:
                    assert choice == 2
                    delim = tube.recvuntil((INPUT_DELIM, LARGE_DELIM))
                    if delim.endswith(LARGE_DELIM):
                        pass
                    else:
                        assert delim.endswith(INPUT_DELIM)
                        if size == 0:
                            pass
                        else:
                            send(b"A" * random.randint(0, size - 1) + b"\n")


def main():
    with connect() as tube:
        if args.FUZZ:
            with open("test", "wb") as fp:
                fuzz(tube, fp)
        tube.recvuntil(LOGIN_DELIM)
        tube.sendline(LOGIN)

        """
        tube.recvuntil(MENU_DELIM)
        tube.sendline(b"2")
        tube.recvuntil(KMEMO_DELIM)

        tube.sendline(b"2")
        tube.recvuntil(OFFSET_DELIM)
        tube.sendline(b"0")
        tube.recvuntil(SIZE_DELIM)
        tube.sendline(b"20")
        tube.recvuntil(INPUT_DELIM)
        tube.sendline(b"A" * 19)

        tube.sendline(b"1")
        tube.recvuntil(OFFSET_DELIM)
        tube.sendline(b"0")
        tube.recvuntil(SIZE_DELIM)
        tube.sendline(b"1024")
        """

        """
        tube.recvuntil(MENU_DELIM)
        tube.sendline(b"2")

        for offset in range(0x1000, 0x800000, 0x1000):
            tube.sendline(b"2")
            tube.sendline(str(offset).encode())
            tube.sendline(b"1")
            tube.sendline()

        for offset in range(0x1000, 0x800000, 0x1000):
            tube.recvuntil(KMEMO_DELIM)
            tube.recvuntil(OFFSET_DELIM)
            tube.recvuntil(SIZE_DELIM)
            tube.recvuntil(INPUT_DELIM)
        """

        tube.interactive()


if __name__ == "__main__":
    main()
