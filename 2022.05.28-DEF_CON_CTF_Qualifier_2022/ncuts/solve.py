#!/usr/bin/env python3
import os
import subprocess
import tempfile

from glob import glob


def exes():
    return [exe for exe in glob("ncuts/*") if os.access(exe, os.X_OK)]


def get_type(exe):
    return subprocess.check_output(["file", exe]).decode().strip()


def solve(exe):
    type = get_type(exe)
    with tempfile.TemporaryDirectory() as workdir:
        env = dict(os.environ)
        env["QEMU_LOG"] = "cpu,op"
        qemu_log_file = os.path.join(workdir, "log")
        env["QEMU_LOG_FILENAME"] = qemu_log_file
        env["QEMU_GDB"] = "1234"
        if "PE32+ executable (console) x86-64" in type:
            argv = ["qemu-x86_64-static", "/usr/bin/wine64", exe]
            env["WINELOADERNOEXEC"] = "1"
        elif "x86-64" in type:
            argv = ["qemu-x86_64-static", exe]
        else:
            argv = [exe]
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        p.stdin.write(str(0x1122334455667788).encode())
        p.stdin.close()
        gdb_p = subprocess.Popen(["gdb-multiarch", "-batch", "-x", "gdbscript", exe])
        result = p.stdout.read()
        p.wait()
        with open(qemu_log_file) as fp:
            log = fp.read()
        return result, log


def main():
    for exe in exes():
        print(exe)
        solve(exe)


if __name__ == "__main__":
    main()
