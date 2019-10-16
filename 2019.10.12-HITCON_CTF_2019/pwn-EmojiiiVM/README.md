# Pwn - EmojiiiVM

See [part1](
https://github.com/mephi42/ctf/tree/master/2019.10.12-HITCON_CTF_2019/reverse-EmojiVM
) for VM structure and [part2](
https://github.com/mephi42/ctf/tree/master/2019.10.12-HITCON_CTF_2019/misc-EmojiiVM
) for programming hints.

The goal here is to pwn the good old EmojiVM. During reversing, the major
problem that stood out was that only `PUSH` and `POP` had explicit overflow and
underflow checks - all the other commands can confidently reach below the stack.
The other problems: lack of trailing `\0` checks in a few places and the ability
to jump outside of the loaded program pale in comparison.

So we can breach the bottom of the stack by doing an `ADD` and then dig deeper
using `POP`, since the latter merely does an equality comparison. What do we
have before the stack anyway?

```
.got:000000000020DDF8 strlen_ptr      dq offset strlen
.data:000000000020E008 dso_handle      dq offset dso_handle
.bss:000000000020E040 stderr          dq ?
.bss:000000000020E180 emoji_code_table db 40h dup(?)
.bss:000000000020E1C0 emoji_data_table db 40h dup(?)
.bss:000000000020E200 gptrs           dq 0Ah dup(?)
.bss:000000000020E260 stack           dq 400h dup(?)
```

Sweet - `gptrs`, which we can thus control, `libc` pointer and self pointer in
case we have a bone to pick with ASLR, and, last but not least, GOT.

By the way, in part 2 the bytecode we submitted could not read from stdin. This
is not the case here: we can exchange information with it and assist it when
e.g. its math capabilities are strained.

First attempt: overwrite `strlen` GOT entry with `system` and trigger
`strlen("/bin/sh")` call by using code `0x14` which does the following:

```
v5 = gptrs[a1];
v3 = strlen(*(const char **)(v5 + 8));
return write(1, *(const void **)(v5 + 8), v3);
```

So, `ADD`, `POP` until `stderr`, `PRINT_QWORD` (for sanity checking), `POP`
until `strlen_ptr`, `PRINT_QWORD` again, `ADD` delta between `system` and
`strlen`, `PRINT_GPTR`, done.

What do you mean, `Segmentation fault`? Turns out it pays off to run `checksec`
every now and then:

```
$ checksec emojivm
[*] 'emojivm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
``` 

[Full RELRO](
https://wiki.debian.org/Hardening#DEB_BUILD_HARDENING_BINDNOW_.28ld_-z_now.29
), goddamnit! So we have to exploit the heap though `gptrs` corruption, aren't
we? Time to study https://github.com/shellphish/how2heap! But first, let's see
what kind of corruptions we can trigger.

Each gptr consists of 2 allocations: 16 bytes for length + pointer metadata, and
as many bytes as we want for the data. If we allocate 10 gptrs containing 15
bytes of data (EmojiVM will add one byte for the trailing zero, making it 16),
all 20 allocated buffers will line up one after the other quite predictably.

* Double free. Add `0x40` to any data pointer to make it equal to the next one,
  and then deallocate the two corresponding gptrs.
* Use after free. Subtract `0x20` from a metadata pointer to make it equal to
  the previous data pointer, then free the corresponding gptr. Since after
  subtraction it will point to all zeroes, freeing the associated data will be
  a no-op. Writing to the previous gptr will overwrite the free chunk.

Actually, that's enough for [tcache poisoning](
https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c
). Here is the plan:

* `ALLOC` x10.
* `ST` the string `sh` into `gptrs[0]` (we have to conserve space, only 1000
  bytes this time).
* `ADD []`: breach the stack bottom.
* `POP` until `gptrs[9]`.
* `SUB [0]`: negate the pointer value.
* `ADD [32]`.
* `SUB [0]`: we'll end up with `gptrs[9] - 0x20`. The whole dance was necessary
  because we could subtract the pointer value from something, but not something
  from pointer value due to the way the memory is laid out.
* `FREE GPTR [9]`.
* `POP` until `stderr`.
* `PRINT_QWORD`: the remote part will read this and compute `__free_hook`
  address for us. Actually it's not a problem to compute this address on the
  EmojiVM side, but then there is no way to load it into gptr.
* `INPUT [8]`: load `__free_hook` address into the free chunk, poisoning tcache.
* `ALLOC`: this will allocate gptr in the last slot, which we previously freed.
  Due to the way tcache poisoning works, the first allocation will return a
  normal healthy chunk, and it will be happily used for gptr metadata. The
  second allocation though will return a poisoned chunk, that is, `__free_hook`
  address. So now we can write into `__free_hook` via newly allocated gptr.
* `INPUT [9]`: load `system` address into `__free_hook`.
* `FREE [0]`: remember that `sh` string we wrote at the beginning? This will be
  now freed, but first it will be passed to `__free_hook`, that is, `system`,
  with a predictable result.

The shell obtained this way allows us to look around on the server and find a
flag.
