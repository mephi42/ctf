## Misc - EmojiiVM

See [part 1](
https://github.com/mephi42/ctf/tree/master/2019.10.12-HITCON_CTF_2019/reverse_EmojiVM
) for VM description.

The goal here is to write out a multiplication table. This is a little bit
awkward, since even though EmojiVM is a stack-based VM, it lacks certain key
primitives like `DUP`. So we need to keep the algorithm as simple as possible.

First attempt: push the pre-generated result on the stack and use command `0x15`
to print it in one go. This works, but it's always a good idea to check the
server first: the limit is just 2000 bytes, so this solution won't fit.

Second attempt: store x and y in gptrs and reload them whenever we need them
(we're not writing an optimizing compiler after all), use a single loop, use
only backward jumps to avoid computing offsets:

```
x = 1;
y = 1;
do {
   print_decimal(x);
   print_string(" * ");
   print_decimal(y);
   print_string(" = ");
   print_decimal(x * y);
   print_string("\n");
   x += 1;
   if (x < 10) continue;
   x = 1;
   y += 1;
} while (y < 10);
```

This works, and server gives us the flag.
