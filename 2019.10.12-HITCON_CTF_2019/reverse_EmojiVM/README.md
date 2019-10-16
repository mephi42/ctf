## Reverse - EmojiVM

We are given a virtual machine interpreter and a bytecode file. Running the
bytecode results in a password prompt. The goal appears to be to figure out the
password.

Let's dig into the interpreter:

```
__int64 __fastcall main(__int64 argc, char **argv, char **envp)
{
  ...
  locale_unbuffer_timeout();
  init_emoji_tables();
  read_bytecode(&bytecode, argv[1]);
  execute_bytecode(&bytecode);
  ...
}
```

There are four functions involved:

* `locale_unbuffer_timeout` configures the terminal.
* `init_emoji_tables` is a giant wall of text that goes like this:

```
v1 = 0x1F233;
*(_DWORD *)std_map_operator[](&emoji_code_table, &v1) = 1;
...
v1 = 0x1F600;
*(_DWORD *)std_map_operator[]v2(&emoji_data_table, &v1) = 0;
```

All the hex values are emoji encodings, as can be easily verified with python's
`chr` function.

* `read_bytecode` reads bytecode into an `std::string`.
* `execute_bytecode` is an interpreter loop.

Inspecting `execute_bytecode` reveals the following:

* EmojiVM has only two registers: program counter and stack pointer. Program
  counter counts characters, not bytes.
* There is a stack which can contain up to 1024 qwords. The granularity is 1
  qword.
* There are 10 so-called gptrs, which are dynamically sized buffers of up to
  1500 bytes. The granularity is 1 byte.
* 23 emojis are mapped to the following commands:
  * `0x01`: no-op.
  * `0x02`: addition: pop two elements, push their sum.
  * `0x03`: subtraction.
  * `0x04`: multiplication.
  * `0x05`: remainder.
  * `0x06`: bitwise xor.
  * `0x07`: bitwise and.
  * `0x08`: less-than comparison: pop two elements, push 1 if the first one is
  less than the second one, push 0 otherwise.
  * `0x09`: equality comparison.
  * `0x0A`: jump: pop an element, set pc to its value.
  * `0x0B`: jump if not zero: pop two elements, jump to the first one if the
    second one is not zero, jump to the next instruction otherwise.
  * `0x0C`: jump if zero.
  * `0x0D`: push a value in range 0-10. The value is encoded as a smiley using
    a separate table, and follows the opcode.
  * `0x0E`: pop.
  * `0x0F`: load from allocated gptr: pop two elements, use the first one as
  gptr index, use the second one as offset into gptr, push the corresponding
  byte.
  * `0x10`: store to allocated gptr.
  * `0x11`: allocate gptr: pop an element, find an unallocated gptr slot,
  allocate gptr of that size.
  * `0x12`: unallocate gptr.
  * `0x13`: read from stdin to gptr.
  * `0x14`: write gptr to stdout.
  * `0x15`: write LSBs of stack values to stdout as characters until 0 is
  encountered.
  * `0x16`: write stack top to stdout as a decimal number, this will not pop the
  value.
  * `0x17`: exit.

Now it's not so hard to write an emulator in python. By running the program and
inspecting the trace we find out the following:

* That's how numbers larger than 10 are normally made:

```
0x00003 PUSH 6
0x00005 PUSH 10
0x00007 MUL [10 6]
0x00008 PUSH 0      # what a lazy codegen :P
0x0000A ADD [0 60]
```

* The password is read into gptr 0.
* The sequence at `0x01A9E` is essentially `strlen()`, the length must be 24
  characters.
* The sequence at `0x02166` prints a crying face. That's where we end up when
  we fail length and other checks.
* Each input character is checked differently. For example, that's the condition
  for the 11th character: `(4 ^ 101 ^ flag[11]) & 255 == 4`.

We're too lazy for this, aren't we? Symbolic execution with `z3` to the rescue!
Let's modify the interpreter to keep track of 24 symbolic characters and feed
them in when asked:

```
predefined_inputs = [[z3.BitVec(f'flag[{i}]', 8) for i in range(24)]]
...
if code == 0x13:
    gptr_element = gptr[stack.pop()]
    if len(predefined_inputs) == 0:
        gptr_element[:len(raw)] = input().encode()
    else:
        gptr_element[:len(raw)] = predefined_inputs.pop(0)
```

Now fix up a few operations to deal with the symbolic world, e.g. replace `==`,
which would otherwise end up doing comparison of Python objects, with a little
bit more elaborate

```
def eq(a, b):
    if type(a) is int:
        cond = b == a
    else:
        cond = a == b
    if type(cond) is bool:
        return 1 if cond else 0
    else:
        return z3.If(cond, 1, 0)
```

This would keep us in the concrete world as long as possible, slipping into
symbolic world only when necessary. What to do with `jnz`? Well, the proper
solution would be to fork two symbolic states and explore them both. But the
`chal.evm` logic is too simple for that. Let's just ask z3 to produce two sample
values for "then" and "else" branches:

```
can_be_0 = check(arg1 == 0)
if str(can_be_0) == 'unsat':
    pc = arg0
else:
    m0 = model(can_be_0)
    cannot_be_0 = check(arg1 != 0)
    if str(cannot_be_0) == 'unsat':
        pc += 1
    else:
        m1 = model(cannot_be_0)
        print(m0)
        print(m1)
        raise Exception('Too dumb to fork')
```

We get:

```
{flag[11]: '\x80', flag[12]: '\x01', ...}
{flag[11]: 'e', flag[12]: '\x01', ...}
Exception: Too dumb to fork
```

Well, now we know 11th character is `e` (no way it's `\x80`). Now let's go back
to symbolic value initialization, set

```
predefined_inputs[0][11] = ord(b'e')
```

and repeat this manually 23 more times. Of course a more elegant solution, which
would involve determining which of the two sets of possible values contains just
one element, is possible, but we just want to solve the goddamn riddle, aren't
we?

Filling all 24 array entries reveals the password, and said password makes the
bytecode print the flag!
