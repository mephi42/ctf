# [sc2elf](https://ctf.bi.zone/challenges/6)

pwn, medium difficulty, 1 solve, 500 points

This utility allows you to convert the shellcode to an ELF executable file.
Hurry up to check it out. All code is compiled to WebAssembly for an extra
layer of security.

`nc sc2elf.2021.ctfz.one 31337`

## TL;DR / links

* [wasm](https://webassembly.org/) binary that converts shellcode to ELF. Runs
  on [Wasmtime](https://wasmtime.dev/).
* Decompile with [wasm-decompile](https://github.com/WebAssembly/wabt).
* The symbols are not stripped, so identify a bunch of functions with the
  interesting names: [`dlfree`](dlfree.dcmp), [`dlmalloc`](dlmalloc.dcmp),
  [`get_result`](get_result.dcmp), [`init_config`](init_config.dcmp),
  [`original_main`](original_main.dcmp), [`set_header`](set_header.dcmp),
  [`set_shellcode`](set_shellcode.dcmp).
* Inline single-use variables with a [simple script](inline.py), beautify the
  rest of the code manually.
* Debug with GDB using the Wasmtime's [`-g` flag](
  https://www.infoq.com/news/2019/09/webassembly-source-level-debug/) to
  get the symbols through the [JIT interface](
  https://sourceware.org/gdb/current/onlinedocs/gdb/JIT-Interface.html) and the
  hidden [`__vmctx->memory`](
  https://github.com/bytecodealliance/wasmtime/pull/1482) local variable to
  inspect the globals.
* Realize that the program just concatenates an ELF header blob with a
  shellcode blob.
* Notice a heap overflow in [`set_shellcode`](set_shellcode.dcmp) and a heap
  UAF in [`get_result`](get_result.dcmp).
* Read the awesome [Everything Old is New Again: Binary Security of
  WebAssembly](
  https://www.usenix.org/conference/usenixsecurity20/presentation/lehmann
  ) paper.
* (Optional) Reel back in horror like an anaconda.
* Correlate the decompiled [`dlfree`](dlfree.dcmp) and [`dlmalloc`](
  dlmalloc.dcmp) with the [wasi-libc sources](
  https://github.com/WebAssembly/wasi-libc/blob/3c4a3f94d1ce685a672ec9a642f1ae42dae16eb1/dlmalloc/src/malloc.c
  ).
* Poison a smallbin with the ELF header blob path address, write the flag path
  there.
* [Exploit](v02-pwnit.py).
* Flag: `ctfzone{A8Rvn4v622vmkbyAeQSRv8gzSD57NLtx}`

## RTFM

WebAssembly (wasm) is a 32-bit stack-based virtual machine for usage in
browsers, which can be targeted by many languages thanks to the LLVM backend.
Wasmtime allows running WebAssembly code outside a browser using a
Cranelift-powered JIT - quite similar to the Node.js / Javascript / V8 combo.

If a wasm runtime implements the WebAssembly System Interface (WASI), which
Wasmtime does, it can be used by the wasm code to interact with the world.
wasi-libc - a mostly POSIX-compatible libc implementation - is built on top of
WASI and provides a customary programming experience.

The most usual wasm memory layout is: executable, stack (grows to 0), heap
(grows from 0); no ASLR, no write protection, no execute protection.

WebAssembly Binary Toolkit (WABT) is basically binutils of the wasm world. In
addition to the usual assembler (`wat2wasm`) and dumpers (`wasm2wat`,
`wasm-objdump`), it provides a relatively simplistic decompiler (
`wasm-decompile`).

## Reversing - static analysis

Having `wasm-decompile` obviates the need to figure out the wasm bytecode, so
fortunately we can skip that part. While decompiled code is miles better than
bytecode, it's still hard to read: every single constant is loaded into a
separate variable, the control flow is obscured by gotos, the stack frames are
managed manually. Since each variable has a unique name, the first problem is
easy to fix with an improvised text-based inliner script. There is not too much
code, so manually identifying ifs/loops, the frame pointer and the local
variable offsets in each function is not that exhausting.

The code works with the following structure:

```
struct config {
  int header_len;
  void *header_buf;
  int shellcode_len;
  void *shellcode;
  int result_len;
  void *result;
};
```

It is initialized by the `init_config` function: the initial header length is
84, the initial shellcode length is 160, the initial result length is 244 and
all three buffers are allocated with `malloc`.

`set_shellcode` parses the base16 input (up to 1k) into a dynamically allocated
buffer (`base16_decode`) and then copies it into the shellcode buffer. Ditto
`set_header`. `get_result` concatenates the header buffer and the shellcode
buffer into the result buffer, which it then prints. If the header buffer does
not start with `b'\x7fELF'`, its contents are replaced with the contents of the
`tmpl/elf.tmpl` file.

## Reversing - dynamic analysis

GDB provides an interface that can be used by JITs to describe the code they
generate. Wasmtime implements this interface and provides symbol addresses
through it when called with `-g` option.

So one can put breakpoints on JITed functions and inspect their arguments (the
ABI uses `%edx` as the first argument and `%ecx` as the second one).
Single-stepping is quite painful though, since the provided line numbers
correspond to the Wasmtime bytecode disassembly, which does not seem to be
saved anywhere.

Furthermore, pointers obtained this way cannot be dereferenced directly. There
actually exists a machinery that can be invoked from a debugger to do this, but
I found it pretty abstract and arcane compared to the following shortcut: many
functions contain a hidden `__vmctx` variable with a single `memory` member.
This member points to a byte array containing the entire wasm memory (it's not
sparse at the moment, but, of course, this can change at any time). Only JITed
functions have this variable, so if the debugger is interrupted during a
syscall, then one needs to change the frame to e.g. `original_main` before
doing e.g. `x/w __vmctx->memory+0x780`.

## Bugs

While `set_header` requires the input to be exactly 84 bytes long,
`set_shellcode` has neither such check nor buffer reallocation logic.
Therefore, we have a classic heap overflow. The initial heap chunks are always
allocated in the same order: header, shellcode, result. So we can overwrite the
result chunk header and the result buffer itself this way.

`get_result` reallocates the result buffer based on the header and the
shellcode sizes. However, it just discards the resulting pointer. This is not
a big deal if the size didn't change, because `malloc` will simply get the old
pointer from a smallbin. However, if the size does change, then we have a
classic use-after-free: `get_result` will write the concatenated blob into the
freed chunk. `set_shellcode` overflow will affect the freed chunk as well.

`get_result` contains another small, but important bug: when the header data is
read from a file, it does not call `fclose`, causing a leak of a `FILE` object.

## Exploitation

There are no RCE gadgets, but we just need to read the flag. Since there is no
ASLR and no write protection, let's try to overwrite the `tmpl/elf.tmpl`
string in the executable's `.data` with the `flag.txt` string. For that we need
to convince `malloc` to return a controlled pointer.

wasi-libc uses dlmalloc, which is what glibc malloc is based on. Since it's
much older, there are no tcache, no fastbins and no unsorted bin. Smallbins are
up to 236 bytes large and have the usual layout, however there is also a
bitmap, which indicates which of them are non-empty. Chunk metadata is also
similar to that of glibc, though instead of arena/mmapped/prev-in-use flags we
have current-in-use/prev-in-use. Large chunks are linked into a tree
structure.

The default size of the result buffer is 244 bytes, which is slightly larger
than 236, which brings us into the large bin tree domain. Figuring this out is
a hassle, so as a first step let's use the shellcode overflow to replace the
large result chunk with two forged small chunks.

wasi-libc allocator sanity checks are different from those of glibc. On the one
hand, there are less of them. But, more importantly, there is the `least_addr`
variable, which tracks the smallest heap address. The heap pointers are
frequently compared with this value, which should prevent poisoning using
executable and stack addresses. However, the challenge executable ignores the
results of these checks, possibly because wasi-libc was built with the
`INSECURE` define (this does not explain why they are still there though, since
`INSECURE` should remove them on the C preprocessor level).

One other obstacle that stands in the way of poisoning is the linking code.
First, let's recap how the smallbin poisoning works. We start with a smallbin
chunk, and let's assume for simplicity it's the only one in the corresponding
smallbin:

```
chunk->fd == bin;
chunk->bk == bin;
bin->fd == chunk;
bin->bk == chunk;
```

Using some vulnerability, we overwrite its links with a controlled address:

```
chunk->fd == poison;
chunk->bk == poison;
bin->fd == chunk;
bin->bk == chunk;
```

and then trigger a `malloc` in order to poison the smallbin through unlinking:

```
#define unlink_first_small_chunk(M, B, P, I) {\
  mchunkptr F = P->fd;\
  ...
  else if (RTCHECK(ok_address(M, F) && F->bk == P)) {\
    F->bk = B;\
    B->fd = F;\
```

The chunk links become irrelevant at this point, the `fd` field of the smallbin
is updated:

```
bin->fd == poison;
bin->bk == chunk;
poison->bk == bin;
```

Note that we also write to the address we poisoned the smallbin with, which is
not a problem, since it's a valid one. The next `malloc` will return the
poison address, but it will also try to unlink it:

```
bin->fd == poison->fd;
bin->bk == chunk;
poison->fd->bk = bin;
```

This is now problematic, since `poison->fd` comes from the executable image and
is most likely part of some string. Fortunately, there is a string ending with
`b'\n\0'` nearby, which in little endian corresponds to `0x000a????`. The
initial heap addresses are like `0x0001????`, so it's possible to abuse the
`get_result` memory leak to expand the heap until `0x000a????` becomes a valid
address. This requires about 500 calls, which is definitely on the slow side,
but is still acceptable.

The last step is to figure out where the two `malloc`s should be triggered
from. Using `get_result` would not work, because its return value is discarded,
so we won't be able to write the path flag into it. The one in `base16_decode`
looks more promising: we can write anything into it, and its size is limited by
its callers (`set_shellcode` and `set_header`) to be no more than 1k, which is
enough. The problem is that `base16_decode` calls are matched with
`base16_free`, which does a `memset`, so whatever we write there will be
erased.

Fortunately, when `base16_decode` encounters a non-base16 character, it
immediately exits with an error, keeping all the data that it decoded so far.
A caller is still expected to free the buffer that it allocated, but neither
`set_shellcode` nor `set_header` do that.

All this combined allows to overwrite the ELF template path, so that the next
`get_result` call leaks the flag.

## Conclusion / venting

This was the first WebAssembly task I ever looked at. It took me about 10 hours
to solve it, in large part because the reversing and especially the debugging
(even with function names) were a pain. Hopefully someone will come up with a
wasm Ghidra plugin and a debuginfo exporter some day.

Another time sink was trying to use LLDB instead of GDB - while in theory it's
way more streamlined, I found its command system to be way too verbose (even
when using short command and subcommand names), and it tends to hang
surprisingly often. It's also missing the [pwntools integration](
https://docs.pwntools.com/en/stable/gdb.html#using-gdb-python-api) at the
moment.

While mitigation-wise the wasm ecosystem looks fairly bleak (no ASLR / 32-bit
address space is prone to brute-forcing anyway, no page protections, way fewer
sanity checks in the libc allocator), without the deactivated `least_addr`
check the challenge might have been significantly harder.

So overall for a wasm newbie like myself I found this challenge to be quite
educational and fair. Someone in the Telegram chat mentioned that they were put
off by the initial decompiler output, but actually inlining the variables and
beautifying the code in the text editor was an easier part.
