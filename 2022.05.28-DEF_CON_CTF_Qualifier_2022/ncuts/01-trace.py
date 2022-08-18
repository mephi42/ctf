from glob import glob
import json
from json.decoder import JSONDecodeError
import multiprocessing
import os
import random
import subprocess
import sys


def trace(exe):
    value_hint = None
    try:
        with open(exe + ".json") as fp:
            existing = json.load(fp)
        existing_value = existing.get("value")
        if existing_value is not None:
            return
        value_hint = existing.get("value-hint")
    except FileNotFoundError:
        pass
    except JSONDecodeError:
        pass
    if os.path.exists(exe + ".trace") and value_hint is None:
        return
    if value_hint is None:
        value_hint = 0
    print(exe + ": tracing")
    type = subprocess.check_output(["file", exe]).decode().strip()
    env = dict(os.environ)
    env["QEMU_LOG"] = "in_asm,op,out_asm,cpu,nochain"
    env["QEMU_STRACE"] = "1"
    env["QEMU_LOG_FILENAME"] = exe + ".trace.tmp"
    env["qEMU_SINGLESTEP"] = "1"
    if "PE32+ executable (console) x86-64" in type:
        # argv = ["qemu-x86_64-static", "/usr/bin/wine64", exe]
        # env["WINELOADERNOEXEC"] = "1"
        return  # the traces are HUGE
    elif "x86-64" in type:
        argv = ["qemu-x86_64-static", exe]
    else:
        argv = [exe]
    argv = ["setarch", "-R"] + argv
    p = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
    )
    stdout, stderr = p.communicate(str(value_hint).encode())
    if b"Congrats!" in stdout:
        with open(exe + ".json", "w") as fp:
            json.dump(
                {
                    "exe": exe,
                    "type": type,
                    "value": value_hint,
                },
                fp,
            )
    os.rename(exe + ".trace.tmp", exe + ".trace")


def main():
    (exe,) = sys.argv[1:]
    exes = [exe for exe in glob(exe) if os.access(exe, os.X_OK)]
    random.shuffle(exes)
    with multiprocessing.Pool() as p:
        p.map(trace, exes)


if __name__ == "__main__":
    main()
