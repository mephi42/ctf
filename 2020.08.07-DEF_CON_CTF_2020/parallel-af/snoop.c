#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fork_count = 0;
static int log_fd = -1;
static int depth = 0;
static char buf[1024 * 1024];

__attribute__((constructor)) void init() {
  snprintf(buf, sizeof(buf), "manchester-%d.log", (int)getpid());
  depth++;
  log_fd =
      open(buf, O_CREAT | O_TRUNC | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
  depth--;
  if (log_fd == -1)
    abort();
}

int intercept_fork(void) asm("fork");
int intercept_fork(void) {
  typedef int (*orig_t)(void);
  orig_t orig = dlsym(RTLD_NEXT, "fork");
  fork_count++;
  return orig();
}

static int hexdump(char *s, size_t s_size, const void *buf, size_t n) {
  size_t written = 0;
  for (size_t i = 0; i < n; i++)
    written += snprintf(s + written, s_size - written, "%02x",
                        ((const unsigned char *)buf)[i]);
  return written;
}

static void write_n(int fd, const void *buf, size_t n) {
  if (fd == -1)
    return;
  size_t pos = 0;
  while (pos != n) {
    ssize_t ret = write(fd, buf + pos, n - pos);
    if (ret == -1)
      abort();
    pos += ret;
  }
}

static const char *insns = NULL;

static void log_send_recv(const void *src, size_t n, _Bool is_send) {
  size_t written = snprintf(buf, sizeof(buf),
                            "{\"worker\": %i, \"op\": \"%s\", \"data\": \"",
                            fork_count, is_send ? "send" : "recv");
  written += hexdump(buf + written, sizeof(buf) - written, src, n);
  if (fork_count == 1 && !is_send) {
    int pc = *(int *)src;
    int index = pc >> 4;
    const void *insn = (const char *)insns + (index * 40);
    written +=
        snprintf(buf + written, sizeof(buf) - written, "\", \"insn\": \"");
    written += hexdump(buf + written, sizeof(buf) - written, insn, 40);
  }
  written += snprintf(buf + written, sizeof(buf) - written, "\"}\n");
  write_n(log_fd, buf, written);
}

struct hash_table {
  unsigned long field_0;
  unsigned long bucket_count;
  struct hash_bucket *buckets;
};

struct hash_bucket {
  unsigned int is_valid;
  unsigned int field_4;
  struct hash_entry *first_entry;
};

struct hash_entry {
  unsigned long r1_key;
  unsigned int pc_key;
  unsigned int field_c;
  unsigned int pc;
  unsigned int field_14;
  unsigned long r0;
  unsigned long r1;
  struct hash_entry *next;
};

static void log_hash_table(long base) {
  size_t written =
      snprintf(buf, sizeof(buf),
               "{\"worker\": %i, \"op\": \"hash\", \"data\": \"", fork_count);
  struct hash_table *h = *(struct hash_table **)(base + 0x2050e8);
  for (unsigned long i = 0; i < h->bucket_count; i++) {
    struct hash_bucket *bucket = &h->buckets[i];
    if (bucket && bucket->is_valid) {
      for (struct hash_entry *entry = bucket->first_entry; entry;
           entry = entry->next) {
        if (entry->r1_key != entry->r1)
          abort();
        if (entry->pc_key != (entry->pc >> 4))
          abort();
        written += hexdump(buf + written, sizeof(buf) - written, &entry->pc,
                           sizeof(entry->pc));
        written += hexdump(buf + written, sizeof(buf) - written, &entry->r0,
                           sizeof(entry->r0));
        written += hexdump(buf + written, sizeof(buf) - written, &entry->r1,
                           sizeof(entry->r1));
      }
    }
  }
  written += snprintf(buf + written, sizeof(buf) - written, "\"}\n");
  write_n(log_fd, buf, written);
}

void *intercept_memcpy(void *dest, const void *src, size_t n) asm("memcpy");
void *intercept_memcpy(void *dest, const void *src, size_t n) {
  typedef void *(*orig_t)(void *, const void *, size_t);
  orig_t orig = dlsym(RTLD_NEXT, "memcpy");
  long ret = (long)__builtin_return_address(0);
  _Bool is_send = (ret & 0xfffL) == 0x740;
  _Bool is_recv = (ret & 0xfffL) == 0x7b0;
  if (is_send || is_recv) {
    if (fork_count == 5)
      log_hash_table(is_send ? ret - 0x2740 : ret - 0x27b0);
    log_send_recv(src, n, is_send);
  }
  return orig(dest, src, n);
}

static void log_open(const char *pathname) {
  size_t written =
      snprintf(buf, sizeof(buf),
               "{\"worker\": %i, \"op\": \"open\", \"path\": \"",
               fork_count);
  written += hexdump(buf + written, sizeof(buf) - written, pathname, strlen(pathname));
  written += snprintf(buf + written, sizeof(buf) - written, "\"}\n");
  write_n(log_fd, buf, written);
}

int intercept_open(const char *pathname, int flags, mode_t mode) asm("open");
int intercept_open(const char *pathname, int flags, mode_t mode) {
  typedef int (*orig_t)(const char *, int, mode_t);
  orig_t orig = (orig_t)dlsym(RTLD_NEXT, "open");
  if (depth == 0)
    log_open(pathname);
  return orig(pathname, flags, mode);
}

static void log_load(size_t size) {
  size_t written = snprintf(
      buf, sizeof(buf), "{\"worker\": %i, \"op\": \"load\", \"size\": %zu}\n",
      fork_count, size);
  write_n(log_fd, buf, written);
}

void *intercept_realloc(void *ptr, size_t size) asm("realloc");
void *intercept_realloc(void *ptr, size_t size) {
  typedef void *(*orig_t)(void *, size_t);
  orig_t orig = (orig_t)dlsym(RTLD_NEXT, "realloc");
  _Bool is_load = ((long)__builtin_return_address(0) & 0xfffL) == 0x007;
  if (is_load)
    log_load(size);
  void *ret = orig(ptr, size);
  if (is_load)
    insns = ret;
  return ret;
}
