#include <assert.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  int ret;
  struct sock_filter filter[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
  struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };

  ret = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  assert(ret == 0);
  char *argv[2] = {"/bin/bash", NULL};
  execve(argv[0], argv, NULL);
}
