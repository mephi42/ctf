## Reverse Engineering - BadType

We are given the Windows binary which wants to have flag as its first argument:

```
> badtype.exe
Usage: badtype.exe <flag>
```

Let's give it something random:

```
> badtype.exe DrgnS{x}
```

A window with the text

```
BAD FLAG!:\
```

appears. Let's have a look in IDA:

```
.text:000000014000252C                 cmp     ecx, 2
.text:000000014000252F                 jz      short length_ok
```

It wants a single argument, that's what we already figured.

```
.text:000000014000254A length_ok:
.text:000000014000254A                 mov     rcx, [rdx+8]
.text:000000014000254E                 mov     [rsp+110h+arg_18], rdi
.text:0000000140002556                 call    processFlag
```

There is a function, to which we pass `argv[1]`. The code that follows creates
a font from a static variable and then does the usual dance: `RegisterClassExW`,
`CreateWindowEx`, etc. Window function displays the "bad flag" message - nothing
notable here. So let's inspect `processFlag`:

```
.text:0000000140001FE0 strlen_flag:
.text:0000000140001FE0                 inc     rax
.text:0000000140001FE3                 cmp     byte ptr [rcx+rax], 0
.text:0000000140001FE7                 jnz     short strlen_flag
.text:0000000140001FE9                 cmp     rax, 50
.text:0000000140001FED                 jnz     done
```

Flag must be 50 characters long.

```
.text:0000000140001FF3                 movups  xmm0, cs:g_magic1
.text:0000000140001FFA                 movups  xmmword ptr [rbp+57h+magic0], xmm0
.text:0000000140001FFE                 movups  xmm1, cs:g_magic2
.text:0000000140002005                 movups  xmmword ptr [rbp+57h+magic1], xmm1
.text:0000000140002009                 movups  xmm0, cs:g_magic3
.text:0000000140002010                 movups  [rbp+57h+magic2], xmm0
.text:0000000140002014                 movzx   eax, cs:g_magicword
.text:000000014000201B                 mov     [rbp+57h+magicword], ax
.text:000000014000201F                 movzx   eax, cs:g_magicbyte
.text:0000000140002026                 mov     [rbp+57h+magicbyte], al
```

The code copies 50 magic bytes from a static variable to stack.

```
.text:0000000140002050 init_bitpairs:
.text:0000000140002050                 lea     rax, [rbp+57h+magic0]
.text:0000000140002054                 add     rax, rsi
.text:0000000140002057                 movzx   ebx, byte ptr [r14+rax]
.text:000000014000205C                 xor     bl, [rax]
```

The entire flag is then XORed with these bytes.

```
.text:000000014000205E                 movzx   eax, bl
.text:0000000140002061                 shr     al, 6
```

```
.text:000000014000208C                 movzx   eax, bl
.text:000000014000208F                 shr     al, 4
.text:0000000140002092                 and     al, 3
```

```
.text:00000001400020BC                 movzx   eax, bl
.text:00000001400020BF                 shr     al, 2
.text:00000001400020C2                 and     al, 3
```

```
.text:00000001400020EC                 and     bl, 3
```

Each XORed byte is then split into 4 bit pairs, which are placed in a vector.

```
.text:0000000140002149                 mov     r8d, RESOURCE_FONT_SIZE
.text:000000014000214F                 lea     rdx, g_font_resource
.text:0000000140002156                 lea     rcx, [rbp+57h+magic0]
.text:000000014000215A                 call    std_string_operator_eq
```

The static font variable (the one that will be used in `main`) is copied into a
string. The memory which used to hold magic bytes now contains this string -
this is going to be somewhat confusing, but oh well.

```
.text:00007FF7C58D2160                 lea     rdx, [rbp+57h+magic0]
.text:00007FF7C58D2164                 lea     rcx, [rbp+57h+tables]
.text:00007FF7C58D2168                 call    parse_font
```

The string is passed to some function - let's skip it for now.

```
.text:00007FF7C58D21A3 find_cff:
.text:00007FF7C58D21A3                 cmp     [rax+table_info.tag], cff_tag
.text:00007FF7C58D21A9                 jz      cff_tag_ok
```

`parse_font` appears to produce an array, and the loop is looking for an entry
containing `CFF ` tag.

```
.text:00007FF7C58D22A2 scan_cff:
.text:00007FF7C58D22A2                 lea     rcx, [rax+rdx]
.text:00007FF7C58D22A6                 movzx   eax, word ptr [rcx]
.text:00007FF7C58D22A9                 cmp     ax, word ptr cs:g_cff_pattern
.text:00007FF7C58D22B0                 jnz     short next_cff
```

In addition to a tag, each array entry contains a string. The code looks for
occurrences of `\x1C\x41\x41` in this string.

```
.text:00007FF7C58D22CF corrupt_1:
.text:00007FF7C58D22CF                 mov     byte ptr [rax+rdx+1], 0
```

```
.text:00007FF7C58D22E9                 movzx   eax, byte ptr [r8]
.text:00007FF7C58D22ED                 mov     [rcx+rdx+2], al
```

It then replaces the second byte with `0` and the third byte with the value of
the next bit pair. There are exactly 200 bit pairs and `\x1C\x41\x41`
occurrences.

```
.text:00007FF7C58D231E                 lea     rdx, [rbp+57h+magic0]
.text:00007FF7C58D2322                 lea     rcx, [rbp+57h+tables]
.text:00007FF7C58D2326                 call    reassemble_font
```

The string and the array are then passed to another function. Let's leave it be
for now.

```
.text:00007FF7C58D2347                 mov     r8, [rbp+57h+magic1]
.text:00007FF7C58D234B                 lea     rcx, g_font_resource
.text:00007FF7C58D2352                 call    memmove
```

Finally, the string is copied back to the static variable. Setting a hardware
watchpoint on `argv[1]` indicates that `processFlag` is the only function where
it's read. So, the code uses the flag to modify the font used to show us the
message, which means we need to find a flag value that modifies the font in a
way that the displayed message changes. For that we need to understand what
these `\x1C\x41\x41` and `\x1C\x00\x00-\x03` thingies are.

What we have is `OTTO` magic at the beginning of the font. This is solid
googling material, and indeed, we immediately learn that this is an OpenType
font. Let's ask Google what is `CFF `: turns out that's Compact Font Format.
Let's have a look at the specs:

* [The OpenType Font File](
https://docs.microsoft.com/en-us/typography/opentype/spec/otff)
* [The Compact Font Format Specification](
http://wwwimages.adobe.com/content/dam/Adobe/en/devnet/font/pdfs/5176.CFF.pdf)
* [Type 2 Charstring Format](
http://wwwimages.adobe.com/content/dam/Adobe/en/devnet/font/pdfs/5177.Type2.pdf)

OpenType files consist of a number of tables, `CFF ` being one of them. Dumping
the original and the modified static font variable values, splitting them into
individual tables and comparing those tables shows that only `CFF ` table is
changed. Good, no suprises. This means we can now focus on CFF spec.

Reading CFF spec reveals that fonts are drawn using a stack-based virtual
machine, which is documented in the Charstring spec. Googling for "python
opentype cff" points to `fonttools` project that we can use to dump the
bytecode. Doing this in a straightforward manner does not work, because it tries
to also run the bytecode, which contains a couple fancy unsupported
instructions, but we can still reuse the lower-level infrastructure and copy
decompilation parts of higher-level infrastructure into our script, while
avoiding running the decompiled code.

Let's dump the charstring:

```
CharStrings[1]
    [0x1] push 1
    [0x2] push 0
    [0x4] put
    [0x5] push 0
    [0x6] push 1
    [0x8] put
    [0x9] push 0
    [0xa] push 2
    [0xc] put
    [0xd] push 1
    [0xe] push 3
    [0x10] put
    [0x11] push 2
    [0x12] push 4
    [0x14] put
    [0x15] push 3
    [0x16] push 5
    [0x18] put
    [0x1b] push 0
    [0x1c] push -96
    [0x1d] callsubr
    [0x20] push 0
    [0x21] push -96
    [0x22] callsubr
    [0x25] push 0
    [0x26] push -96
    [0x27] callsubr
    [0x2a] push 0
    [0x2b] push -96
```

```
    [0x3fe] push 0
    [0x3ff] push -96
    [0x400] callsubr
    [0x401] push 0
    [0x403] get
    [0x404] push 41
    [0x406] eq
    [0x407] push 1
    [0x409] get
    [0x40a] push 40
    [0x40c] eq
    [0x40e] add
    [0x40f] push 2
    [0x411] eq
    [0x413] not
    [0x414] push -99
    [0x416] add
    [0x417] callsubr
    [0x418] endchar
```

Instructions `0x1-0x18` initialize the transient array (let's call it `t`) with
`[1, 0, 0, 1, 2, 3]`. We then see a ton of calls to `subr11` (actual subroutine
numbers are computed by adding a bias - in this case `107`, to `callsubr`
arguments) - it's their arguments which are encoded as `\x1C\x00\x00-\x03`. So
the code passes each bit pair to `subr11`.

At the end `subr9` is normally called, but if  `t[0] == 41` and `t[1] == 40`,
then `1` is added to a subroutine number and the code calls `subr8` instead.
This must be the goal here: find which values to pass to `subr11` so that the
desired `t[0]` and `t[1]` values are produced. Let's dump `subr11`:

```
    localSubrs[11]
        [0x1] push 0
        [0x2] push 1
        [0x3] push 0
        [0x4] push 3
        [0x6] index
        [0x8] ifelse
        [0x9] push 0
        [0xa] push 1
        [0xb] push 3
        [0xd] index
        [0xe] push 3
        [0x10] ifelse
        [0x12] add
        [0x14] not
        [0x15] push -98
        [0x17] add
        [0x18] callsubr
```

If bitpair is out of bounds, `subr9` is called. It seems to be a bad thing -
let's keep in mind that we should avoid `subr9` being ever called. If the check
succeeds, however, then `subr10` is called. Dumping it reveals that it contains
a single `return` instruction - a good thing apparently.

```
        [0x19] push 0
        [0x1a] push 1
        [0x1b] push 0
        [0x1c] push 0
        [0x1e] get
        [0x20] ifelse
        [0x21] push 0
        [0x22] push 1
        [0x23] push 0
        [0x24] push 1
        [0x26] get
        [0x28] ifelse
        [0x29] push 0
        [0x2a] push 1
        [0x2b] push 0
        [0x2d] get
        [0x2e] push 42
        [0x30] ifelse
        [0x31] push 0
        [0x32] push 1
        [0x33] push 1
        [0x35] get
        [0x36] push 40
        [0x38] ifelse
        [0x3a] add
        [0x3c] add
        [0x3e] add
        [0x40] not
        [0x41] push -98
        [0x43] add
        [0x44] callsubr
```

Ditto `t[0]` and `t[1]`.

```
        [0x45] push 1
        [0x47] get
        [0x48] push -91
        [0x4a] add
        [0x4b] callsubr
```

Here we call a subroutine with index `t[1] + 16`. Since we know that
`0 <= t[1] <= 40` we can assume that this would call `subr16` - `subr56`.
These subroutines check whether `t[0]` belongs to a certain set, and if yes,
call the dreaded `subr9`. Each of them has a unique associated set, otherwise
they are all the same. For example:

```
    localSubrs[17]
        [0x1] push 0
        [0x2] push 0
        [0x4] get
        [0x5] push 0
        [0x7] eq
        [0x9] add
        [0xa] push 0
        [0xc] get
        [0xd] push 4
        [0xf] eq
        [0x11] add
        [0x12] push 0
        [0x14] get
        [0x15] push 12
        [0x17] eq
        [0x19] add
        [0x1a] push 0
        [0x1c] get
        [0x1d] push 24
        [0x1f] eq
        [0x21] add
        [0x22] push 0
        [0x24] get
        [0x25] push 38
        [0x27] eq
        [0x29] add
        [0x2a] push 0
        [0x2c] get
        [0x2d] push 42
        [0x2f] eq
        [0x31] add
        [0x33] not
        [0x34] push -98
        [0x36] add
        [0x37] callsubr
        [0x38] return
```

This basically means that if `t[1] == 1`, then `t[0]` cannot be one of
`[0, 4, 12, 24, 38, 42]`. Let's continue `subr11` analysis.

```
        [0x4c] push 2
        [0x4e] add
        [0x50] get
        [0x51] push -95
        [0x53] add
        [0x54] callsubr
```

This calls subroutine `t[bitpair + 2] + 12`. Since `t[2:6]` are in range `0-3`,
this will call `subr12`-`subr15`. They are responsible for incrementing and
decrementing `t[0]` and `t[1]`, for example:

```
    localSubrs[12]
        [0x1] push 0
        [0x3] get
        [0x4] push 1
        [0x6] add
        [0x7] push 0
        [0x9] put
        [0xa] return
```

We can see that `subr12` increments `t[0]`. Let's finish `subr11`.

```
        [0x55] push -50
        [0x56] callsubr
        [0x57] return
```

At the end it calls `subr57`.

```
    localSubrs[57]
        [0x1] push 2
        [0x3] get
        [0x4] push 3
        [0x6] get
        [0x7] push 4
        [0x9] get
        [0xa] push 5
        [0xc] get
        [0xd] push 4
        [0xe] push 1
        [0x10] roll
        [0x11] push 5
        [0x13] put
        [0x14] push 4
        [0x16] put
        [0x17] push 3
        [0x19] put
        [0x1a] push 2
        [0x1c] put
        [0x1d] return
```

This one rotates `t[2:6]`, for example, if it's `[0, 1, 2, 3]`, then it will
become `[3, 0, 2, 1]`. Ok, where to go from here?

It's useful to think about `t[0]` and `t[1]` as `x` and `y` coordinates
`subr12`-`subr15` allow us to walk right, down, left and up respectively.
`subr16`-`subr56` define where we can't go, that is, walls. We start at `(0, 0)`
and need to reach `(41, 40)`.

First, let's extract the labyrinth map. Doing this manually by analyzing
`subr16`-`subr56` is boring, so let's use symbolic execution with `z3`. It's
enough to have just one symbolic variable `t[0]` and simulate each subr
individually. There are about 10 instruction types, so the simulator code fits
on a single screen. When we reach `callsubr`, we need to find all values of
`t[0]` that satisfy `subr == 9` - they will be our walls.

Second, let's convert the wall information to a `networkx` graph and find the
shortest path from `(0, 0)` to `(41, 40)`.

Third, let's convert the path to bitpairs. We already have the simulator, so
let's reuse it to run the whole charstring. Whenever we find ourselves calling
`subr11`, let's replace the actual argument value with the one computed based on
the following observations. Let's recap that movement happens using
`t[bitpair + 2] + 12` and `t[2:6]` rotate each turn. The latter circumstance
does not complicate life, because we simulate everything anyway and thus know
the current `t` value when we need to make a decision. So the task is to compute
`bitpair` based on direction of the current step and current value of `t`, and
this is trivial.

Finally, we need to squash bitpairs into bytes and xor them with magic bytes.
This reveals the flag!