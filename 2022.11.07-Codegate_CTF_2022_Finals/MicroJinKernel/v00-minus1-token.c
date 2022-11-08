#include <stddef.h>

/* Syscalls. */

#define __NR_creat 0x10001
#define __NR_alloc 0x10002
#define __NR_close 0x10003
#define __NR_copy_from_guest 0x10004
#define __NR_copy_to_guest 0x10005
#define __NR_read_write 0x10006
#define __NR_read_write_vec 0x10007

#define CMD_READ 0x38273
#define CMD_WRITE 0x38274

typedef int fd_t;
typedef long token_t;

struct vec {
  long fd;
  long cmd;
  long save;
};

static inline long xsyscall(int number, long arg1, long arg2, long arg3,
                            long arg4) {
  register long rax asm("rax") = number;
  register long rdi asm("rdi") = arg1;
  register long rsi asm("rsi") = arg2;
  register long rdx asm("rdx") = arg3;
  register long rcx asm("rcx") = arg4;
  asm volatile("syscall"
               : "+r"(rax)
               : "r"(rdi), "r"(rsi), "r"(rdx), "r"(rcx)
               : "memory");
  return rax;
}

static inline fd_t xcreat(const void *path, size_t path_size) {
  return (fd_t)xsyscall(__NR_creat, (long)path, (long)path_size, 0, 0);
}

static inline token_t xalloc(int fd, size_t size) {
  return (token_t)xsyscall(__NR_alloc, (long)fd, (long)size, 0, 0);
}

static inline int xclose(fd_t fd) {
  return (int)xsyscall(__NR_close, (long)fd, 0, 0, 0);
}

static inline int xcopy_from_guest(token_t token, size_t offset, size_t size,
                                   void *buf) {
  return xsyscall(__NR_copy_from_guest, (long)token, (long)offset, (long)size,
                  (long)buf);
}

__attribute__((used)) static int xcopy_to_guest(token_t token, size_t offset,
                                                size_t size, const void *buf) {
  return xsyscall(__NR_copy_to_guest, (long)token, (long)offset, (long)size,
                  (long)buf);
}

static inline int xread(fd_t fd) {
  return xsyscall(__NR_read_write, (long)fd, CMD_READ, 0, 0);
}

static inline int xwrite(fd_t fd) {
  return xsyscall(__NR_read_write, (long)fd, CMD_WRITE, 0, 0);
}

static inline void xread_write_vec(struct vec *vecs, size_t count,
                                   long *retvals) {
  xsyscall(__NR_read_write_vec, (long)vecs, (long)count, (long)retvals, 0);
}

/* Payload. */

__attribute__((section(".entry"))) void entry(void) {
  int fd = xcreat("test", 5);
  // assert(fd == 0);
  token_t token = xalloc(fd, 5);
  (void)token;
  struct vec vecs[255];
  long retvals[256];
  for (size_t i = 0; i < 255; i++) {
    vecs[i].fd = fd;
    vecs[i].cmd = CMD_READ;
    vecs[i].save = 1;
  }
  xread_write_vec(vecs, 254, retvals);
  xclose(fd);
}
