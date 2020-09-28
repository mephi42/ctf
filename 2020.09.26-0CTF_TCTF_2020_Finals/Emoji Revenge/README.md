# Emoji Revenge

## Description

You don't really know EMOJI.

```
nc chall.0ops.sjtu.edu.cn 31323
```

[Attachment](emoji_revenge_fa784c596d62ae5d3f0cf1a04d03910d.tar.gz)

## Summary

This is a pwn challenge. We are given a small binary that speaks emoji:
```
Welcome to 🅰️  ⭐️  0️⃣  ⭐️  ⓔ
🐴: Don't frighten my horse.
🐮: Miaow miaow miaow
🍺: 🐮🍺
```
That's pretty much it. Let's go.

## TL;DR

* [Exploit](pwnit.py)
* Inspired by: PlaidCTF 2020 [EmojiDB](https://ctftime.org/task/11311) ([my
  solution](../../2020.04.17-PlaidCTF_2020/EmojiDB/pwnit.py))
* [Glibc bug](https://sourceware.org/bugzilla/show_bug.cgi?id=20568)
* [mmap_min_addr](https://www.kernel.org/doc/Documentation/sysctl/vm.txt)
* [UTF-32 to UTF-8](https://stackoverflow.com/a/42013433/3832536)
* Send 🍺 in a loop until `mmap()` returns `NULL`.
* Send 🐴 with shellcode at offset 0, infinite loop at offset 0x200, and
  70 🐮s at the end.
* Wait until `SIGALRM` happens.
* The shell appears:
```
$ cat flag
flag{thanks_again_Plaid_CTF_i_found_th1s}
```

## Reversing

* `main()` contains initialization and menu loop, the choices available being:
🐴, 🐮 and 🍺.
* Initialization does the following:
```
  setlocale(LC_ALL, "en_US.UTF-8");
  fputws("W", stdout);
  srand(time(NULL));
  signal(SIGALRM, on_alarm);
  alarm(30);
```
* 🍺 does this:
```
  g_page = mmap(
    /* addr   */ (void *)((rand() % 1000) << PAGE_SHIFT),
    /* length */ PAGE_SIZE,
    /* prot   */ PROT_READ | PROT_WRITE | PROT_EXEC,
    /* flags  */ MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,
    /* fd     */ -1,
    /* offset */ 0LL);
  if (g_page == MAP_FAILED) {
    fputws("map() failed!\n", stdout);
    abort();
  }
  wprintf(L"map() at @%p\n", g_page);
  g_inited = 1;
```
In a nutshell, it maps and prints an address of a random RWX page in 0x0 -
0x3e8000 range. Nothing stops us from calling it multiple times.
* 🐮 puts the following code into 🍺-allocated page and jumps to it:
```
# data
g_page:
  "🌶️  💩  💉  💧  🐮  🍺"

# code
g_page + 0x200:
  .byte 0x41, 0x41;
  nop * 15;
  syscall(__NR_write, STDOUT_FILENO, g_page, 0x26);
  syscall(__NR_exit, 0);

# entry trampoline
g_page + 0x400:
  %rsp -= 0x8000;
  memset(%rsp - 0x8000, 'a', 0x10000);
  %rax = %rbx = /* all the other GPRs except %rsp */ = $0xdeadbeefdeadbeef;
  goto g_page + 0x200;
```
`0x41, 0x41` bytes end up being some sort of a weird nop. In any case, we have
no control over what this code is doing.
* 🐴 is like 🐮, but lets us input 0x208 bytes of data. The bytes
  `[0x100:0x200]` are then overwritten by `'a'`s. The bytes `[0x202:0x208]`
  are overwritten by nops. So we control `[0x0:0x100]` and `[0x200:0x202]`.

## Shellcoding

It's kind of clear what needs to be done. We need to place shellcode somewhere
at the first 0x100 bytes and then use 2 bytes to somehow jump there.

The first problem is that we input UTF-8, but then `fgetws()` converts it to
UTF-32. So we need to input UTF-8, whose UTF-32 representation will be the
desired shellcode. So on the exploit side, we need to split the shellcode into
4-byte chunks, treat them as code points, and convert each of them to UTF-8.
Conveniently, there is [an algorithm](
https://stackoverflow.com/a/42013433/3832536) to do just that. The only
limitation is that the top bit of each code point cannot be 1. This is very
easy to work around by just adding some nops.

## Code golfing (not)

Now the fun part begins - we need to place a 2-byte instruction at 0x200 that
would jump to at least 0xfe. Or maybe the instruction can be longer, but the
bytes after the 2nd one have to be 0x90s.

Short relative (8-bit) jumps are exactly 2 bytes long, but they don't work,
since their range is limited to 0x80 in either direction, and the distance we
need to cover is at least 0x102.

"Medium" (16-bit) jumps are not available on x86_64. 32-bit jumps end with way
too many 0x90s in the most significant offset bytes to be useful. Ditto
`xbegin` - that would've been so cool though.

Stack and registers contain junk, so things like `pop` + `jmp` or `push` +
`ret` are not viable. Or are they? How about `pushfq` + `ret`? `pushfq` would
give us something small, and sending a few thousand 🍺s to the server confirms
that [`mmap_min_addr`](https://www.kernel.org/doc/Documentation/sysctl/vm.txt)
is set to 0 and `mmap` sometimes returns `NULL`. The problem is that the
interrupt flag is always set, and its value is 0x200. So `pushfq` will always
give us values larger than 0x200, and we will not be able to jump to
`[0x0:0x100]`, where our shellcode lives.

Scrolling through Intel Manual does not yield anything useful, and neither
does [brute forcing opcodes](brute.py). There are a bunch of single-byte
instructions that mess with `%rax`, like `lahf`, but they are either not
available on x86_64 or don't zero out `%rax`, so things like `lahf` + `jmp
%rax` are out of the question.

Dead end.

## Googling

From the experience with PlaidCTF's EmojiDB challenge I was familiar with "bug
in Glibc" CTF trope, so, `fgetws` being the most obvious candidate here, I
googled for things like `fgetws vulnerable`, `fgetws overflow`, `fgetws
security`, `fgetws vulnerability`, `fwgets bug`, `fgetws segfault`, `fgetws
crash` and even `fgetws site:https://sourceware.org/bugzilla/`. Nothing.

But it was the silliest of them all that brought the breakthrough: `fgetws
ubuntu`. [`Using fgetws after setting a UTF-8 locale?`](
https://stackoverflow.com/q/40975450/3832536)
```
... Clang 3.8.1 on Ubuntu 16.10 with -std=c11 , -std=c++11 , -std=c++14 , and
-std=c++17 all exhibit this weird behaviour when using fgetws(buf, ...
```
Weird behavior, I love these. And challenge's init also sets UTF-8 locale!

The StackOverflow question talks about memory corruption, contains thorough
analysis, [code reference](
https://sourceware.org/git/?p=glibc.git;f=libio/wfileops.c;hb=glibc-2.29#l490)
and a [Glibc Bugzilla link](
https://sourceware.org/bugzilla/show_bug.cgi?id=20938). The bug is still open,
however, the code in [looks different](
https://sourceware.org/git/?p=glibc.git;f=libio/wfileops.c;hb=glibc-2.30#l511)
in the next glibc version. Note that it passes `wnread`, and not `delta`, to
`__libio_codecvt_length`. So, why was it changed?

[`Fix crash in _IO_wfile_sync (bug 20568)`](
https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=32ff39753371)
```
When computing the length of the converted part of the stdio buffer, use
the number of consumed wide characters, not the (negative) distance to the
end of the wide buffer.
```

Finally, here is our [Bug 20568 - Segfault with wide characters and
setlocale/fgetwc/UTF-8](https://sourceware.org/bugzilla/show_bug.cgi?id=20568).
It triggers when `atexit()` handler calls `_IO_unbuffer_all()` and there are
unconsumed wide characters in stdin.

Here comes another CTF trope: most of the challenge code is there for a reason.
In this case it manifests itself through the usage of `_exit()` and `abort()`
all over the place: these functions do not trigger `atexit()` handling. The
return from `main()` is guarded by `_exit()`. The author clearly wants to make
reaching `atexit()` handling hard, which is a sign that we are on the right
path. The only place where `exit()` is called is `on_alarm()` function.

## PoC

Let's try to run the [PoC](poc.c) from the Bugzilla. Fire up Docker, compile,
run, aand - nothing. Quick single-stepping through `_IO_wfile_sync()` shows
that we don't reach `__libio_codecvt_length()`, because `delta` is 0, and there
is no action in `fp->_wide_data` whatsoever. Some brooding brought me to the
conclusion that this is simply because the Docker image lacks `en_US.UTF-8`
locale. And indeed, adding it to the [image](image/Dockerfile) finally allowed
to trigger the crash.

## Exploitation

So, 2 bytes at `g_page + 0x200` are not for jumping to the shellcode. They are
for creating an infinite loop, that would eventually trigger `SIGALRM`. We
can't just wait in `fgetws()`, because then we won't have any unconsumed stdin
bytes. We rather need to send 🐴, shellcode and on top of that some garbage -
all in a single chunk.

Anyway, why do we crash and what do we control?

In [`do_length()`](
https://sourceware.org/git/?p=glibc.git;f=libio/iofwide.c;hb=glibc-2.29#l328)
function we have a VLA:

```
  wchar_t to_buf[max];
```

where `max` ends up being negative. Its exact value depends on the amount of
unconsumed bytes, and can thus be perfectly controlled. `to_buf` is an output
buffer for converting unconsumed data from UTF-8 to UTF-32, so it looks as if
it can be used to write anything to any stack offset. Unfortunately, that's not
the case, because `to_buf` end is less than `to_buf`, and therefore the
coversion is a no-op.

However, there is another consequence of `max` being negative: stack frames of
`do_length()`'s callees begin to overlap with its own stack frame. So even
though said callees won't write anything into `to_buf` through conventional
means, their local variables may still overlap something valuable. Like a
return address. And it's not too unreasonable to assume that some of these
locals might be zeroes.

So I just brute forced the junk size - most of the time the end result was
stack cookie overwrite, jump to an (uncontrolled) garbage addresses or
referencing random memory, until at the value of 70 I hit jump to 0. The end.

Well, kind of. It took like 5 minutes before `mmap()` returned 0 on the server,
but then, finally:
```
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Closed connection to chall.0ops.sjtu.edu.cn port 31323
[+] Opening connection to chall.0ops.sjtu.edu.cn on port 31323: Done
[*] Switching to interactive mode
🐴: Don't frighten my horse.
🐮: Miaow miaow miaow
🍺: 🐮🍺
🐴😓
😈
$ pwd
/
$ cat flag
flag{thanks_again_Plaid_CTF_i_found_th1s}
```

## Conclusion / Moaning / Bragging

Moral of the story: by going through Glibc Bugzilla one can find
security-relevant bugs that are not being fixed for years. I bet employees of
various three-letter agencies are given ample time to do just that. Scary,
isn't it? On the bright side, `mmap_min_addr` is actually a very good idea.
Also, while knowing CTF tropes [might not be particularly useful](
https://www.youtube.com/watch?v=lxJpKUoX-6E) in the real life, it is helpful,
well, during CTFs.

I spent more time on this task than I am comfortable to admit, and a
significant portion of it has been quite frustrating. Especially the way the
challenge was masquerading itself as code golf (at least that was my
impression), while the real issue was completely different - felt a little bit
mean.

That said, the way all the small observations I made came together and finally
made sense at the end was very satisfying. So props to the author :-)
