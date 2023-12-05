#include <syscall.h> // for __NR_read
#include <unistd.h>  // for STDIN_FILENO

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

extern void shellcode_end(void);

__attribute((section(".entry"))) void entry(void) {
  xsyscall3(__NR_read, STDIN_FILENO, (long)shellcode_end, 1000);
  shellcode_end();
}
