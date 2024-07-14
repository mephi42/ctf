#include <syscall.h>
#include <unistd.h>

static long xsyscall(int number, long arg1, long arg2, long arg3, long arg4,
                     long arg5, long arg6) {
  register long rax asm("rax") = number;
  register long rdi asm("rdi") = arg1;
  register long rsi asm("rsi") = arg2;
  register long rdx asm("rdx") = arg3;
  register long r10 asm("r10") = arg4;
  register long r8 asm("r8") = arg5;
  register long r9 asm("r9") = arg6;
  asm volatile("syscall"
               : "+r"(rax)
               : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
               : "rcx", "r11", "memory", "cc");
  return rax;
}

static ssize_t xread(int fd, void *buf, size_t count) {
  return xsyscall(__NR_read, fd, (long)buf, count, 0, 0, 0);
}

static void readn(int fd, void *buf, size_t count) {
  while (count != 0) {
    ssize_t n = xread(fd, buf, count);
    if (n < 0) {
      __builtin_trap();
    }
    buf += n;
    count -= n;
  }
}

extern char _end[];

__attribute__((section(".entry"))) void _start(void) {
  readn(STDIN_FILENO, _end, STAGE1_SIZE);
  asm volatile("jmp _end");
  __builtin_trap();
}
