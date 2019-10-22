# Reversing - runme

This sweet little program just wants us to run it, and in exchange for this
unweighty trifle it will give us the flag! How nice of it!

But maybe let's first have a short look in IDA? It starts with the quite
predictable `open`-`malloc`-`read`-`close` dance, but then it forks,
increments a 16-bit counter:

```
.text:080489E3 memset_0_done:
.text:080489E3                 call    _fork
.text:080489E8                 mov     [esp+0F0h+pid], eax
.text:080489EC                 movzx   eax, [esp+0F0h+incme_after_fork]
.text:080489F1                 add     eax, 1
.text:080489F4                 mov     [esp+0F0h+incme_after_fork], ax
.text:080489F9                 cmp     [esp+0F0h+pid], 0
.text:080489FE                 jz      in_child
```

hashes a 16-byte buffer we've just `memset` to all zeroes:

```
.text:08048A04 in_parent:
.text:08048A04                 mov     [esp+0F0h+arg1], 10h
.text:08048A0C                 lea     eax, [esp+0F0h+buf]
.text:08048A10                 mov     [esp+0F0h+arg0], eax
.text:08048A13                 call    hash_md5_val
.text:08048A18                 cmp     [esp+0F0h+incme_after_fork], 0
.text:08048A1E                 jns     incme_after_fork_ge_0 ; 2**15 times
```

goes through a bunch of `nop`s:

```
.text:08048B2A in_child:                               ; CODE XREF: main+101↑j
.text:08048B2A                 nop
```

falls through to waiting for its child:

```
.text:08048B3F incme_after_fork_ge_0:                  ; CODE XREF: main+121↑j
.text:08048B3F                 call    _wait
.text:08048B44                 jmp     memset_0_done
```

and repeats the whole sequence until 16-bit counter's sign bit does not become
1, that is, 2 ** 15 times. This means that that many processes will be spawned
at a time. That's not a proper fork bomb yet, but it's not hard to imagine that
a reasonable person would still find this rude and not acceptable.

So, let's defuse the evil contraption?

```
# skip fork
b *0x080489E3
commands
  set $eip = 0x080489E8
  set $eax = 1
  c
end

# skip wait
b *0x08048B3F
commands
  set $eip = 0x08048B44
  c
end
```

The code runs quite quickly and orderly under this gdbscript. Instead of
creating new processes, it does all the hashing inside of the main one, and
then, as intended, uses the result as an AES key to decrypt the flag.
Unfortunately, this produces total garbage. Where is the catch?

Let's try to recap how the program is supposed to work, given infinite time
and resources:

```
main:
  memset(buf, 0, sizeof(buf))
  for _ in range(2 ** 15):
    hash(buf)
    child0:
      wait()  # should return -1, errno=ECHILD
      for _ in range(2 ** 15 - 1):
        hash(buf)
        child1:
          ...
          exit(0)
        wait(child1)  # should return 0 and set *wstatus = 0
        decrypt()
        exit(0)
    wait(child0)  # should return 0 and set *wstatus = 0
  decrypt()
  exit(0)
```

So, the whole action is sequential, despite the number of involved processes.
Children will create each other recursively, each ultimately hashing the buffer
2 ** 15 times and saving the decrypted flag to the disk, overwriting each
other's work. Finally, the parent would save its own decrypted version,
overriding what the last child did. This should be the correct flag.

The bothersome thing is:

```
.text:08048B3F                 call    _wait
.text:08048B44                 jmp     memset_0_done
```

Where is the argument? Where will `wstatus` be saved? This is a 32-bit program,
so all the arguments are passed on stack. The last time something was put on
top of the stack was:

```
.text:08048A0C                 lea     eax, [esp+0F0h+buf]
.text:08048A10                 mov     [esp+0F0h+arg0], eax
.text:08048A13                 call    hash_md5_val
```

This is the buffer that is being hashed! So, sneakily, in addition to hashing,
the code overwrites the first 32 bits of the buffer with wstatus, which is
supposed to always be zero. It could be possible to enhance gdbscript to
simulate that, but now it's also possible to simply implement the whole logic in
Python. Doing this correctly decrypts the flag:
`SECCON{infinite_fork_is_not_good_for_system}`. It sure isn't.
