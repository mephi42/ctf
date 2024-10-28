#include <stdio.h>
#include <unistd.h>

#define UID_MAP_FILENO 6

int main(void) {
  int stdout_fds[2];
  pipe(stdout_fds);
  dup2(UID_MAP_FILENO, STDIN_FILENO);
  dup2(stdout_fds[0], STDOUT_FILENO);
  dprintf(stdout_fds[1], "sandbox1\n");
  while (1) {
    pause();
  }
}
