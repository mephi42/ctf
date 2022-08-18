#!/usr/bin/env python3
import re
from collections import defaultdict
from glob import glob
import hashlib
import json
from json.decoder import JSONDecodeError
import multiprocessing
import os
import random
import subprocess
import sys
import time
import traceback


MD5_TO_BYTE = {hashlib.md5(bytes((i,))).digest(): i for i in range(0x100)}
MD5_RE_STR = (
    b"(?:"
    + b"|".join(
        "".join("\\x{:02x}".format(md5_byte) for md5_byte in md5_bytes).encode()
        for md5_bytes in MD5_TO_BYTE.keys()
    )
    + b")"
)
MD5_RE = re.compile(MD5_RE_STR)


def try_value(exe, type, value):
    env = dict(os.environ)
    env["QEMU_LOG"] = "in_asm"
    if "PE32+ executable (console) x86-64" in type:
        argv = ["qemu-x86_64", "/usr/bin/wine64", exe]
        env["WINELOADERNOEXEC"] = "1"
    elif "x86-64" in type:
        argv = ["qemu-x86_64", exe]
    else:
        argv = [exe]
    p = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    stdout, stderr = p.communicate(str(value).encode())
    assert len(stderr) != 0
    # print(stderr)
    return b"Congrats!" in stdout, len(stderr.split(b"\n"))


def solve_1(exe):
    t0 = time.time()
    type = subprocess.check_output(["file", exe]).decode().strip()
    try:
        with open(exe + ".json") as fp:
            existing = json.load(fp)
        existing_value = existing.get("value")
        if existing_value is None:
            return
        print(exe + ": checking " + str(existing_value))
        p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(str(existing_value).encode())
        p.stdin.close()
        stdout = p.stdout.read()
        p.wait()
        if b"Congrats!" in stdout:
            print(exe + ": correct")
            return
        print(exe + ": wrong")
        os.unlink(exe + ".json")
    except FileNotFoundError:
        pass
    except JSONDecodeError:
        os.unlink(exe + ".json")
    print(exe + ": solving")
    with open(exe, "rb") as fp:
        buf = fp.read()
    possible_digits = []
    for m in MD5_RE.findall(buf):
        possible_digits.append(MD5_TO_BYTE[m])
    for i in range(0x100):
        if i not in possible_digits:
            impossible_digit = i
            break
    else:
        raise Exception("impossible_digit")
    t1 = time.time()
    init_t = t1 - t0
    if len(possible_digits) == 0:
        with open(exe + ".json", "w") as fp:
            json.dump({"exe": exe, "type": type, "err": "no md5", "init_t": init_t}, fp)
        return
    possible_digits = sorted(set(possible_digits))
    # print(possible_digits)
    digits = [impossible_digit] * 8
    endian = range(8)
    endian_reversed = False
    while impossible_digit in digits:
        for i in endian:
            if digits[i] != impossible_digit:
                continue
            n_lines2digits = defaultdict(list)
            for digit in possible_digits:
                digits[i] = digit
                value = sum(digits[j] << (j * 8) for j in range(8))
                # print(hex(value))
                digits[i] = impossible_digit
                ok, n_lines = try_value(exe, type, value)
                if ok:
                    with open(exe + ".json", "w") as fp:
                        json.dump(
                            {
                                "exe": exe,
                                "type": type,
                                "value": value,
                                "init_t": init_t,
                                "solve_t": time.time() - t1,
                            },
                            fp,
                        )
                    return
                n_lines2digits[n_lines].append(digit)
            # print(n_lines2digits)
            if len(n_lines2digits[max(n_lines2digits.keys())]) == 1:
                digits[i] = n_lines2digits[max(n_lines2digits.keys())][0]
            else:
                if not endian_reversed:
                    endian = reversed(endian)
                    endian_reversed = True
                else:
                    raise Exception("wtf")
                break


def solve(exe):
    try:
        return solve_1(exe)
    except:
        print(exe + ": exception")
        traceback.print_exc(file=sys.stdout)
        raise


def main():
    (exe,) = sys.argv[1:]
    exes = [exe for exe in glob(exe) if os.access(exe, os.X_OK)]
    random.shuffle(exes)
    with multiprocessing.Pool() as p:
        p.map(solve, exes)


if __name__ == "__main__":
    main()
