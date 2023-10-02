/* 11 bytes or less */

__attribute__((noreturn, section(".entry"))) void entry(void) {
  /* %rax (number) is already __NR_read == 0 */
  /* %rdi (fd) is already STDIN_FILENO == 0 */
  /* ~%dl (len) is 0xff */
  asm("lea 0f(%rip),%rsi\n"
      "not %dl\n"
      "syscall\n"
      "0:");
  __builtin_unreachable();
}
