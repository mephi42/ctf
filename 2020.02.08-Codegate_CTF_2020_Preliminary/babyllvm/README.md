# babyllvm

# Summary

The challenge is RCE-as-a-service, with a twist, that what's executed is pure
[brainfuck](https://en.wikipedia.org/wiki/Brainfuck), and execution environment
is a JIT based on [llvmlite](https://github.com/numba/llvmlite), which
implements sandboxing by emitting bounds checks. The goal is to find a bug in
JIT and/or runtime library, and use it to escape the sandbox.

# JIT logic

## Step 1 - Parsing

A brainfuck program is represented as a tree. Each node is either a linear node,
or a loop node. Loop nodes consist of the part before the loop, the loop, and
the part after the loop.

## Step 2 - Optimization

Linear nodes are converted to `shortened_code` form, which uses the following
opcodes:

1. `ptr += imm`
2. `*ptr += imm`
3. `imm.times { print(*ptr); }`
4. `imm.times { read(ptr); }`

## Step 3 - Runtime

Runtime is implemented as a shared library. It contains data area, which is
0x3000 byte large, and is preceded by `data_ptr` and `start_ptr` pointers, as
well as function used to perform bounds checking. `checksec` shows only partial
RELRO, which hints at the potential to overwrite GOT.

## Step 4 - JIT

Codegen of linear nodes tries to be smart regarding optimizing away bounds
checks. opcode 1 allows arbitrary changes, but also tracks the position of data
pointer relative to what it was at the start of the block (`rel_pos`). Opcodes
2-4 compare this relative position to the statically tracked range, for which
bounds checks were already emitted (`whitelist`), and emit the check only when
it's outside of that range. Each generated check extends the range in order
to avoid unnecessarily repeating checks in the future.

Codegen of non-linear nodes recursively generates code for its three nested
programs, and glues them together.

Codegen returns `(entry, exit)` tuple, where entry and exit are either basic
blocks, or tuples of similar shapes. `exit` may be `None`, which means there is
just one linear basic block.

# Vulnerability

The bug is here:

```
			br1b = self.br1.codegen(module, (0, 0))
			br2b = self.br2.codegen(module, (0, 0))
```

When generating the loop body, we assume that we don't need to generate the
bounds check for the initial pointer position, since it's already a part of the
code that glues together three parts of the loop node.

However, generation of the glue itself is guarded by:

```
			if not is_safe(0, whitelist):
```

Which means that the nested loop will have no bounds checks whatsoever.
Therefore we can move the data pointer to an unsafe position in the parent loop,
since it's not checked anyway, and then dereference it in the nested loop.

# Pwn

Here is the safe leak of the `start_ptr`'s least significant byte:
`+[<<<<<<<<[.>>>>>>>>>]]`. It works by storing `1` to `data[0]` in order to enter
the parent loop, positioning the data pointer on `data[-8]`, dumping it in the
child loop, and then going to `data[1]` in order to exit both child and parent
loops.

This cannot be used to dump bytes equal to `0`, because we won't enter the child
loop and the program will trip on the parent loop's bounds check, but
fortunately we know that interesting pointers are of the form
`0x0000xxxxxxxxxxxx`, so we can limit ourselves to reading just 6 bytes.

GOT is located close to the beginning of the data area. By using the leak above,
we can read any slot and locate libc. By replacing `.` with `,` we can overwrite
any slot with one_gadget address. I went with overwriting `write` with
`libc + 0x10a38c`, which gave me the shell.

# Flag

`CODEGATE2020{next_time_i_should_make_a_backend_for_bf_as_well}`

I wanted to try doing just that a few years back, but never managed to find the
time :-(
