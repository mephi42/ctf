## Reversing - random_pitfalls

We are given the binary, which:

* `mmap`s 64 consecutive `PROT_NONE` pages.
* Randomly selects 32 of them, and `mprotect`s them to `PROT_READ|PROT_WRITE`.
* Places 40-byte random values into the first 31 of them.
* Places `flag ^ value[0] ^ ... ^ value[30]` into the last one.
* Disables all syscalls except `write(1, buf, 40)` and `exit`.
* Reads shellcode from stdin.
* Prepends a prologue, which clears all general purpose registers except `rdi`
  and `rsi` (including `rsp`!).
* Calls the shellcode, passing the address of the first page as `rdi` and the
  address of the buffer as `rsi`.

The gist of the task is to find a way to determine whether a page is readable
without relying on the OS. Indeed, we need to correctly determine which 32 pages
are mapped, and xor all the corresponding 40-byte values in order to get the
flag. An incorrect guess would lead to a segfault, and on the next attempt we'll
see some completely new new values.

Still, the way pages are randomly chosen looks a bit weird, let's write a
similar loop in python and see if the distribution it produces is biased.. no,
for all practical intents and purposes, it's not.

Second guess - Spectre-like approach, when we would try to provoke speculative
accesses to those pages and measure differences in timings. Sounds complicated,
let's leave this as a last resort.

Third guess - a specialized machine instruction. Let's check out Volume 2 of
Intel Manual. And let's start with Chapter 5 (V-Z) and move backwards, because
is's fun (no, seriously, that was the solution process!). The first instruction
we encounter this way is: `XTEST - Test If In Transactional Execution`. This
particular one is irrelevant, but - What Happens To Page Faults If In
Transactional Execution?

Quick test:

```
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static inline int is_mapped(void *p) {
    long long rax;
    asm("mov $-1,%%rax\n"
        "xbegin 0f\n"
        "mov 0(%[p]),%%rbx\n"
        "xend\n"
        "0: mov %%rax,%[rax]\n"
        : [rax] "=r" (rax) : [p] "r" (p) : "rax", "rbx");
    return rax == -1;
}

int main() {
    assert(getpagesize() == 4096);
    void *m0 = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(m0 != MAP_FAILED);
    void *m1 = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(m1 != MAP_FAILED);
    *(long long *)m1 = 1;
    for (;;) {
        assert(!is_mapped(m0));
        assert(is_mapped(m1));
    }
}
```

The code loads `-1` into `rax`, initiates a transaction, dereferences a pointer,
and ends a transaction. When transaction is aborted for whatever reason, `rax`
receives a reason code (`-1` is not a valid reason code), otherwise it stays as
is. Turns out a page fault is a completely valid reason to abort a transaction
without calling an interrupt handler! That's why, by the way, `*(long long *)m1
= 1` is very important in this test, pages allocated by `mmap` are mapped only
on first access, which, if it happens inside a transaction, never reaches the
`#PF` handler.

With that knowledge, implementing shellcode is trivial, and we get the flag:
`SECCON{7h1S_ch4L_Is_in5p1r3d_by_sgx-rop}`. The SGX ROP article turned out to be
fantastic, by the way - a very much recommended read.
