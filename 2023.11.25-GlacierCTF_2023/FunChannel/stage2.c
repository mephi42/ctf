#include <fcntl.h>   // for O_RDONLY, AT_FDCWD
#include <syscall.h> // for __NR_openat, __NR_getdents, __NR_read

static long xsyscall3(int number, long arg1, long arg2, long arg3) {
  register int rax asm("rax") = number;
  register long rdi asm("rdi") = arg1;
  register long rsi asm("rsi") = arg2;
  register long rdx asm("rdx") = arg3;
  asm volatile("syscall\n"
               : "+r"(rax), "+r"(rdx)
               : "r"(rdi), "r"(rsi)
               : "rcx", "r11", "memory", "cc");
  return rax;
}

static long xstrlen(const char *s) {
  long l = 0;
  while (s[l])
    l++;
  return l;
}

struct linux_dirent {
  unsigned long d_ino;     /* Inode number */
  unsigned long d_off;     /* Offset to next linux_dirent */
  unsigned short d_reclen; /* Length of this linux_dirent */
  char d_name[];           /* Filename (null-terminated) */
};

__attribute__((noreturn)) __attribute((section(".entry"))) void entry(void) {
  int dirfd =
      xsyscall3(__NR_openat, AT_FDCWD, (long)".", O_RDONLY /*| O_DIRECTORY*/);
  while (1) {
    unsigned char buf[128];
    unsigned short nread =
        xsyscall3(__NR_getdents, dirfd, (long)buf, sizeof(buf));
    for (unsigned short bpos = 0; bpos < nread;) {
      struct linux_dirent *d = (struct linux_dirent *)(buf + bpos);
      if (*(int *)&d->d_name[xstrlen(d->d_name) - 4] == 0x7478742e /* .txt */) {
        int fd = xsyscall3(__NR_openat, dirfd, (long)d->d_name, O_RDONLY);
        xsyscall3(__NR_read, fd, (long)buf, sizeof(buf));
        if (buf[IDX] OP VAL) {
          __builtin_trap();
        } else {
          asm volatile("jmp .");
          __builtin_unreachable();
        }
      }
      bpos += d->d_reclen;
    }
  }
}
