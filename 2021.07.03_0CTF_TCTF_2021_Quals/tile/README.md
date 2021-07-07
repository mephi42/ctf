# tile

pwn, 2 solves, 916 points

An old IoT device. [attachment](tile_90b9c4bf6faed82517df394f8be3e9d7.tar.gz)

`http://111.186.59.27:28088`

## TL;DR / links

* [TILE-Gx](https://en.wikipedia.org/wiki/TILE-Gx) ELF binary implementing a
  HTTP server.
* [ISA reference](
  https://nanopdf.com/download/tile-gx-instruction-set-architecture_pdf).
* Build [QEMU](https://git.qemu.org/?p=qemu.git) v5 (TILE-Gx is removed in v6)
  with `--target-list=tilegx-linux-user`, play with the binary.
* Build [afl++](https://github.com/AFLplusplus/AFLplusplus) with [this patch](
  0001-tilegx.patch), find crashes in the basic authentication handling.
* QEMU GDB stub is broken, use tracing with [`-singlestep -d in_asm,cpu
  -strace`](ctf.xinetd.patch) instead.
* Build [binutils](https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git)
  with `--target=tilegx-linux-gnu`, decompile objdump output [by hand](
  httpd.dcmp) - the code appears to be built with `-O0`, so it's simple, but
  tedious.
* Understand the crashes: username and password are essentially `strcpy()`ed
  into `alloca(32)`ed buffers.
* Check mitigations: no ASLR (binary, heap and stack are all at known
  locations), no NX (heap is executable), stack canary present.
* Use the username overflow to overwrite the password pointer with the address
  of the return address, bypassing the canary.
* Overwrite the return address with the shellcode address (on heap).
* Realize that the remote server may have slightly different stack addresses
  (due to argv, envp, and especially auxv) and brute force the delta.
* [Exploit](v02-pwnit.py).
* Flag: `flag{rop_on_t1111111le-gx_is_funny_27b7d3}`.

## Fuzzing

As I learned from CFZone 2021's FuzzAN-US challenge, afl++ supports foreign
architectures with its QEMU instrumentation, so I tried building it for
TILE-Gx:

```
qemu_mode$ CPU_TARGET=tilegx ./build_qemu_support.sh
```

Unfortunately, `afl-fuzz` refused to run, stating that handshake with
forkserver has failed. I had to debug and figured out that the instrumented
code does not call `shmat(getenv(SHM_ENV_VAR))`. QEMU's tilegx implementation
does not use the common `translator_loop()`, to which afl++ adds its
initialization, but rather implements a similar loop on its own. Adding the
similar logic there fixed the issue.

By looking at `strings` output it's possible to figure out what subset of HTTP
the binary implements:

- `GET`, `HEAD` and `POST` methods.
- `Content-Length`, `Host` and `Authorization` (`Basic`) headers.

Admin credentials (`admin:70p_s3cr37_!@#`) are also there. That's enough to
give afl++ some initial input data to work with, and indeed, after several
minutes it finds a bunch of crashes by passing weird data with the
`Authorization` header.

## Debugging

When trying to connect to QEMU GDB stub, GDB (both from Ubuntu 20.04 and
binutils master) thinks the other side is sending garbage, and bails. I've
decided against trying to fix that and went with inspecting the trace that
QEMU writes when invoked with `-singlestep -d in_asm,cpu -strace` flags.
`-singlestep` makes it trace each instruction, instead of each basic block,
`-d in_asm` shows correspondence of program counter values to instructions,
`-d cpu` shows register values after each instruction, and `-strace` shows
the syscalls.

Traces produced this way aren't too large and can be navigated using vim or
even `grep -C`. Knowing that it's better to debug in the remote-like
environment, I also added these flags to the xinetd config and used `docker
exec grep` to look at the data.

## Static analysis

There don't seem to be good tools to decompile TILE-Gx (there is a plugin
from Talos, but it's for the Linux version of IDA, which I don't have), so
I've decided to manually work with the objdump output. The local variables
in the binary are constantly spilled and loaded back (most likely because
it's built with `-O0`). Even though it means that a single line of code
corresponds to like 10 assembly instructions, it's easy to keep track of
frame offsets (as opposed to register juggling in optimized code) and
recognize many patterns (e.g. loading constants with `moveli` +
2 x `shl16insli` or function calls).

Knowing the crash location, I probably could have gotten away with not
decompiling as much code as I did, but I wanted to be sure I understood what
was happening. The code works with the following structures:

```
struct req {
  /* 0x00 */ void *;
  /* 0x08 */ void *method;
  /* 0x10 */ void *uri;
  /* 0x18 */ hdr *hdr;
  /* 0x20 */ char *content;
  /* 0x28 */ long content_length;
  /* 0x30 */ char *host;
  /* 0x38 */
};

struct hdr {
  /* 0x00 */ char *name;
  /* 0x08 */ void *value;
  /* 0x10 */ hdr *next;
  /* 0x18 */
};
```

First, [`sub_1001378`](httpd.dcmp#L274) reads the request from stdin, then
[`sub_1003750`](httpd.dcmp#L1525) handles it and prints the response to
stdout, and finally [`sub_1002270`](httpd.dcmp#L797) frees the request
memory. `sub_1003750` calls [`sub_1002f98`](httpd.dcmp#L1258) to check the
`Authorization` header. It uses [`sub_10054b0`](httpd.dcmp#L2516) to decode
base64-encoded credentials, splits them by `:`, and ...

## Bug

... does `alloca(32)` two times and copies the username and the password to the
resulting buffers without any length checks whatsoever.

## Exploitation

The stack layout is as follows:

```
+-----------+  <- stack top
| password  |
+-----------+
| username  |
+-----------+
| &password |  <- username overflow -\
+-----------+                        |
| &username |                        |
+-----------+                        |
| ......... |                        |
+-----------+                        |
|  cookie   |                        |
+-----------+                        |
|  retaddr  |  <---------------------/
+-----------+
```

The code copies the username first, so we can use the overflow there to
overwrite the password pointer. The new value can point to the return
address, bypassing the cookie. From here on one could just write a ROP, but
there is an even easier way: shellcode.

A few years back I made a similar challenge - [Learning the Ropes](
../../2019.11.30-CTFZone_2019/pwn-Learning_the_Ropes), where the goal was to
make players write ROP for [IBM Z](https://en.wikipedia.org/wiki/IBM_Z).
However, some of them realized that the version of QEMU the challenge was
running on did not implement all the memory protections, and simply jumped to
shellcode on stack.

Here it's not that simple, because the copying is done until `'\0'`, and
writing shellcode without `'\0'`s in it might be more challenging than
writing a ROP chain. However, there is still a base64-decoded array on
the heap. Since there is no ASLR either, it has a fixed address.

The last problem was that the exploit failed very early on the remote system.
Of course, my approach with hardcoding a bunch of addresses is fragile, but on
the other hand the docker environments should be identical. Finally, I
realized, that while I tried to keep argv and envp the same, auxv is managed by
the kernel and cannot be easily manipulated. So I ran exploit in a loop, trying
different stack offsets, and at 16 it clicked. So, there must have been one
extra auxv element on the server.

## Conclusion

Quite an interesting challenge - a tribute to a dying architecture (the
TILE-Gx support is being removed from everywhere). The bug is not that
complicated, but this is compensated by the lack of reversing tools - it's
nice that afl++ could be easily made to work though. Judging by the flag, the
intended solution must have been a ROP chain, but a known QEMU deficiency
allowed me to get away with the shellcode.
