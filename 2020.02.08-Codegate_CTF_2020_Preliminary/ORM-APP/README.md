# ORM-APP

# Summary

The challenge consists of two parts - a custom CPU emulator, and a program that
runs on this emulator. The goal is to find and exploit a vulnerability in this
program.

# Executable file format

The file starts with the header, which has the following format:

* `uint32_t magic` - signature.
* `uint32_t word_size` - 4 for 32-bit variant, 8 for 64-bit variant. `chal.ormb`
is 64-bit.
* `uint64_t entry` - virtual entry point address.
* `uint32_t stack_size` - stack size in bytes. `chal.ormb` has 16k stack.
* `uint32_t n_sections` - number of sections.

It is followed by sections, which have the following format:

* `uint64_t addr` - virtual address.
* `uint64_t virt_size` - virtual (loaded) size.
* `uint32_t file_size` - size on disk, can be less that `virt_size`.
* `uint32_t prot` - rwx protection bits.
* `uint8_t data[file_size]` - contents.

# Machine architecture

Machine has:

* 1 data register (ORM = One Register Machine, as we'll discover later).
* Program counter.
* Two stacks, which grow towards each other.
* Memory (sections + stack mapped at random address).
* I/O ports.
* Memory-mapped I/O.

# Instruction set

Instructions are 8-bit and have the following format: `OOOOOXYY`, where `O` is
opcode. Meanings of `X` and `Y` vary from instruction to instruction, but the
general trend is that `X` selects one of two stacks, and `Y` describes the
argument: 0 means immediate, 1 means top of stack 0, 2 means top of stack 1, and
3 means register. The execution uses dispatch table indexed by `O`:

```
0: exit
1: stack push
2: stack pop
3: `-` if y == 0 else `~`
4: `+`
5: `-`
6: `*`
7: `/`
8: `%`
9: `>>` (unsigned)
10: `>>` (signed)
11: `<<`
12: `&`
13: `|`
14: `^`
15: `==`
16: `!=`
17: `>` (unsigned)
18: `>=` (unsigned)
19: `>` (signed)
20: `>=` (signed)
21: jump
22: jump if zero
23: jump if not zero
24: stack peek
25: i/o write if x == 0 else i/o read
26: call if x == 0 else ret
27: memory store absolute
28: memory store indirect
29: memory load absolute
30: invalid
31: invalid
```

# I/O ports

The following ports are defined:

```
1272: write mmio mode (better be 2)
1273: write mmio base address
1274: initiate mmio start / mmio wait
1275: read 1 character from stdin
1276: write 1 character to stdout
1277: read i/o error code
```

I think issuing two `mmio start` requests in a row may result in a race related
to pthread creation in the emulator, but this must be for the second task of the
series. Shout-out to PPP, who are the only team who have solved it!

# Reversing

Of interest are two code sections and two data sections. The first code section
contains libc-like helper functions: `read`, `write`, `atoi`, etc. The second
code section contains the application logic (`add`, `show` and `migrate`). The
first data section contains read-only static data, including the flag. The
second data section (think `.bss`) contains user input, number of projects,
project pointers and projects themselves.

Projects have the following structure:

* `uint8_t name[8]`
* `uint8_t description[0x80]`
* `uint64_t is_migrated`

# Vulnerability

There is space only for 8 projects, but projects may be added indefinitely. When
the 9th project is added, its pointer overlaps the `name` field of the first
project. Unfortunately it's not possible to change the name or the description
of an already added project.

I have to admit, I did not fully understand how it happens, but when migrating
a project with a corrupted name, we can gain program counter control.

Roughly, the corrupted name is passed to `sub_8000000373`. The key property of
corruption is that pointers contain 8 non-zero bytes, while names are assumed to
be 0-terminated and contain 7 characters. `sub_8000000373`, judging by the use
of `(*~x & 0x8080808080808080) & ( *x - 0x101010101010101)` primitive, in one
way or the other computes the length of the passed string. It's assumed it ends
up being less that 8.

However, when it's greater, what follows the first 8 bytes is spilled onto the
stack and is not cleared. The final `ret` jumps to the first spilled word, which
we fully control.

# Pwn

We need to write ROP that would write flag address into the first project
pointer and jump back to `main`. Then showing the first project will reveal the
flag.

There are two gadgets:

```
0x8080808080808668: pop stk1
0x8080808080808669: ret stk1
```

and

```
0x8080808080808554: stq stk1
0x8080808080808555: ret stk1
```

The first one allows to load anything into the register. The second one allows
to write anything to memory pointed to by the register. There is no ASLR and
all addresses are known. So we have 3-step rop:

1. Load the address of the first project pointer into the register.
2. Store flag address into memory pointer to by the register.
3. Jump to `main`.

# Flag

`CODEGATE2020{ROP@One_Register_Machine:):)}`
