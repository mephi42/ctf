## Reversing - 7w1n5

We are given two binaries, both of which print:

```
Let's start analysis! :)
```

and immediately exit. Under `gdb` they also print:

```
No no no no no
```

and still exit.

Inspection with IDA reveals a soup of encryption calls, environment checks and
`exec`s. Let's try dynamic analysis first in order to figure out where these two
messages are printed, and how it detects `gdb`. The first theory is `ptrace`
system call, of course, so let's use `strace` to verify it:

```
$ strace -f -s 8192 -o strace.out ./Brother1
```

No `ptrace`. What are those `exec`s doing?

```
$ grep exec < strace.out
execve("/bin/bash", ["./Brother1", "-c", " " * 4096 +
"#!/bin/bash\n
echo \"Let's start analysis! :)\"\n
ps -a|grep -v grep|grep -e gdb -e \" r2\" -q &&
  echo \"No no no no no\" &&
  exit 1\n
echo Close! So close! >/dev/null\n
for I in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15\n
do\n
  date +" + "x" * 770 + "SECCON{Which_do_yo|tr A-Za-z N-ZA-Mn-za-m >/dev/null &
  # base64\343\201\253\343\201\252\343\201\243\343\201\246\343\201\204\343\202\213\n
done\n
echo Close! So close! >/dev/null\n",
"./Brother1"], /* 62 vars */) = 0
```

Ok, it just looks for `gdb` and `r2` in the process list, so we can simply use a
symlink to trick it. Wait a second, what's this: `SECCON{Which_do_yo`?

```
$ strace -f -s 8192 ./Brother2 2>&1 | grep exec
execve("./Brother2", ["./Brother2"], /* 62 vars */) = 0
execve("/bin/bash", ["./Brother2", "-c", "exec '/usr/bin/strace' \"$@\"",
"./Brother2"], /* 63 vars */) = 0
execve("/usr/bin/strace", ["/usr/bin/strace"], /* 63 vars */) = 0
```

`argv[0]` trick, how cute.

```
$ strace -f -s 8192 bash -c ./Brother2 2>&1 | grep exec
execve("/bin/bash", ["./Brother2", "-c", " " * 4096 +
"#!/bin/bash\n
echo \"Let's start analysis! :)\"\n
ps -a|grep -v grep|grep -e gdb -e \" r2\" -q &&
  echo \"No no no no no\" &&
  exit 1\n
echo Close! So close! >/dev/null\n
for I in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15\n
do\n
  date +" + "x" * 770 + "u_like_Bin_or_TxT}|tr A-Za-z N-ZA-Mn-za-m >/dev/null &
  # base64\343\201\253\343\201\252\343\201\243\343\201\246\343\201\204\343\202\213\n
done\n
echo Close! So close! >/dev/null\n",
"./Brother2"], /* 62 vars */) = 0
```

Hard to believe, but `SECCON{Which_do_you_like_Bin_or_TxT}` is indeed the flag!
