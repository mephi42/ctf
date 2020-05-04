# code_runner

# Summary

After a PoW check, the server generates a MIPS binary, sends it base64-encoded
to us, and then runs it. The binary checks 64 bytes we supply to its stdin, and
in case it's happy, it lets us give it some shellcode to run. The catch is that
generates binaries are kind of different, and there is a time limit.

# Analysis

Even though there is PoW, it's still possible to download a significant amount
of samples. I let the script to run in the background, and it ended up collecting
about 1000. The `main()` function is always like this:

```
int main() {
  gettimeofday(&dt, NULL);
  if (checker()) {
    gettimeofday(&t1, NULL);
    dt.tv_usec = ((t1.tv_sec - dt.tv_sec) * 1000000 + t1.tv_usec) - dt.tv_usec;
    if (dt.tv_usec / 100000 < 13)
      read(0, shellcode, 0x34);
    (*(code *)shellcode)();
```

This means we have 1.3 seconds to find something that the checker would accept.
The first two layers are always the same:

```
uint checker() {
  puts("Faster > ");
  read(0,input,0x100);
  checker_trampoline(input);
```

followed by

```
uint checker_trampoline(uchar *input) {
  return checker0(input);
```

What follows are 16 chained checkers, each of which inspects 4 bytes:

```
uint checker0(uchar *input) {
  if ((input[1] == input[3]) && (input[0] == input[2]) &&
      (input[0] == -0x26) && (input[3] == 0x1a))
    return checker1(input + 4);
  else
    return 0;
}
```

and the final checker is always the same:

```
uint checker16(uchar *input) {
  return 0xc001babe;
}
```

# Attempt 1: angr

This looks simple enough for [angr to solve](angr.py). Indeed, angr cuts through
most checkers like a hot knife through butter. What gives it pause are nonlinear
checkers like this one:

```
uint checker3(uchar *input) {
  x1 = input[2] * input[2] - input[1] * input[1];
  if (x1 < 0) x1 = -x1;
  x2 = input[3] * input[3] - input[0] * input[0];
  if (x2 < 0) x2 = -x2;
  if (x2 <= x1) {
    x1 = input[3] * input[3] - input[2] * input[2];
    if (x1 < 0) x1 = -x1;
    x2 = input[0] * input[0] - input[1] * input[1];
    if (x2 < 0) x2 = -x2;
    if (x1 < x2)
      return checker4(input + 4);
    }
  }
  return 0;
}
```

The good news is that there is always a solution, where inputs are either `0`
or `1`, so trying each checker with such an extra constraint first lets us get
past those without adding any explicit signatures.

This puts us at 15 seconds under pypy3 though, and despite the presence of some
glaring inefficiencies, like starting symbolic execution at the very entry
point, it's highly unlikely that we can get to 1.3s. So this approach has to
be scrapped.

# Attempt 2: grouping and signatures

Since `checker_trampoline()` is always the same, and each checker follows the
same pattern:

```
if (!cond1) goto fail;
if (!cond2) goto fail;
...
return checker_n+1(input + 4);  # jal ADDR
fail:
return 0;                       # jr ra
```

we can very quickly identify and extract every single one of them from all
samples, and then do a pairwise [`difflib.SequenceMatcher().ratio()`](
https://docs.python.org/3/library/difflib.html#difflib.SequenceMatcher.ratio) on
them in order to find similar groups.

There are certain immediately noticeable thresholds: 98% and 70%. Using 98%
produces groups that differ only by constant values (good), but there are way
too many of them to further handle manually. Using 70% produces a more
manageable amount of groups, however, the differences within each group are
quite significant - it's not only register numbers, but sometimes also sequences
of instructions.

I'm pretty sure an AV guru could've make it work, but having stared at samples
for quite some time, I knew that I would have more luck with the next approach.

# Solution: signatures + DIY femtoangr

angr has a lot of nice features, like using a proper IR and forking states, but
this challenge doesn't really need them, and they appear slow us down. What we
need is converting an essentially linear sequence of checks into a constraint
and letting z3 solve it.

There are only ~20 various MIPS instructions in collected samples, so it was
fairly easy to write [such a convertor](emu.py). There are a bunch of places
where we can cheat and get away with it: not handling overflows, considering all
"branch taken" events as lava and matching `abs()` by signature.

Combined with nearly instantaneous extraction of checkers from the second
approach this puts us at 0.2 seconds, which is more than enough.

There are plenty of MIPS shellcodes floating on the internet, I ended up used
[this one](
https://packetstormsecurity.com/files/105611/MIPS-execve-Shellcode.html),
because it fit somewhat tight space requirements. The [combined exploit](
pwnit.py) worked!

# Flag

`De1ctf{9d94bc3d3f57f1b33aee728b5d32d6d473df8df3}`
