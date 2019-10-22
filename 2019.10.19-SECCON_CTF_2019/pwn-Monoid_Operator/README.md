# Pwn - Monoid Operator

The binary we are given asks for an operator (add, multiply or xor), the number
of unsigned 64-bit integers and their values. It then applies the operator to
the integers, prints the result, and asks for more things to do. In case the
addition or the multiplication overflows, `Overflow is detected` message is
printed, and the loop continues. Finally, the code asks for a name and a
feedback, and does `sprintf(&stack_buffer, feedback);`.

It is clear what to do at the end: once we know the libc address, we can compute
the location of a [one_gadget](https://github.com/david942j/one_gadget) and the
stack canary. Even though we are not allowed to have any [`n` letters](
https://github.com/hellman/libformatstr) in feedback, `%s` is more than enough
to fill canary and return address stack slots.

But how to leak a libc address? There is a hint: the code checks the return
value of the first `scanf` (operator), but not the second (number of integers)
and the third (values) ones'. So, it we input garbage instead of numbers, we can
trick the code into summing the uninitialized values returned by `malloc`. The
best thing we can hope for is a free list containing the address of one of the
bins, which resides inside libc (e.g. unsorted bin).

Unfortunately, the allocation pattern appears to be very limited: a sequence of
`malloc` - `free` pairs. Because of this, we never end up having free list
pointers inside our chunk.

However, there is a catch: `Overflow is detected` message is the only one
printed to stderr, whose buffer is initialized lazily. So, if we trigger this
message, we can diversify our allocation pattern just enough to get the coveted
free list pointers. A simple test shows that the following sequence:

```
int main() {
    setlinebuf(stderr);
    long long *p = malloc(130 * 8);
    assert(p);
    fwrite("Overflow is detected.\n", 1uLL, 0x16uLL, stderr);
    free(p);
    p = malloc(130 * 8);
    assert(p);
```

results in `p[0]` and `p[1]` being back and forward pointers to libc. So the
exploitation plan is:

* Add 130 numbers: `0xffffffffffffffff`, `2` and 128 `0`s.
* Add another 130 numbers: `0` and `x`. We will get the same chunk as the last
  time, but with back and forward pointers. `0` will clear the back pointer, and
  `x` will make sure that the rest of the buffer - which is a forward pointer
  and a bunch of zeroes from the last time, will stay intact. Wait, isn't that
  just two elements? Yes, but since `x` is not a number, it will be stuck in the
  `scanf` buffer and will therefore count as 129 "empty" numbers and the next
  operator, which will finally consume it.
* The result of the second addition is thus a libc pointer, from which we can
  compute gadget and cookie pointers.
* Send the carefully crafted format string as feedback and get the shell.

A few observations regarding forming the format string:

* We can set a breakpoint at the `sprintf` call and observe stack and register
  values. Many of them reliably end with `0x00`, which means we'll be able to
  use them as zero byte. `%8$c` serves this purpose very nicely.
* We can use padding modifier to produce multiple characters at once, e.g.
  `%8$1032c` will produce 1031 spaces and a zero.
* The cookie always starts with `\0`, so `%.8s` would copy just that. We need to
  first use `%8$c` to produce `\0` and then use `%.7s` on an incremented cookie
  address.
* The gadget address always ends with `\0\0`, so a similar consideration
  applies.
* The gadget might require a certain stack slot to be zero. More `%8$c`s to the
  rescue!

With that, we can get the flag:
`SECCON{MATh3mat|c$_s0MEt1m3S_Dr!v3s_prOgRam_cra2y}`.
