# qmemo

```
mephi42: Why is qmemo a sandbox challenge? It's pure pwn 🙂
Piers: to afflict mental pain onto unsuspecting pyjail player
```

## Goal

This is the third challenge out of three in the fullchain challenge series. In
the [kmemo](../kmemo) challenge we obtained root in a VM, now it's time to get
a shell on the host.

The author has provided the source code for the vulnerable QEMU device.

I found the information leak bug quite quickly, but finding the arbitrary write
took until almost the end of the CTF, even though I noticed something was wrong
in that area in the very beginning, so I solved the challenge only the next
day. Sigh.

# Device

The device uses 3 different ways to interact with the guest:

* Port I/O.
* Memory-mapped I/O.
* DMA.

Port I/O is used to send command codes to the device and get the response
codes. MMIO is used for passing small data, and DMA is used for passing pages.

The following commands are defined:

* `CMD_STORE_GETKEY`: start a new writing session. A new key is generated and
  provided to the guest. On the host, two files are created: `/tmp/mp_<KEY>`
  and `/tmp/mp_<KEY>-data`. The first contains 4-byte page indices and the
  second one contains 4k pages themselves.
* `CMD_STORE_PAGE`: store a page to the data file, and append its index to the
  in-memory array.
* `CMD_STORE_FIN`: flush the in-memory page index array to disk, close the
  writing session.
* `CMD_LOAD_SETKEY`: start a new reading session using a key. Load the page
  indices from disk into an in-memory array.
* `CMD_LOAD_PAGE`: return the next page index from the array and the next page
  from the data file to the guest.
* `CMD_LOAD_FIN`: close the reading session.

## Vulnerabilities

`CMD_LOAD_PAGE` has no bounds checks. One can read many more page indices than
was written, leaking the host heap to the guest.

MMIO code checks whether the start address is within the MMIO range, but not
the end:

```
static uint64_t pci_memodev_mmio_read(void *opaque, hwaddr addr, unsigned size) {
        PCIMemoDevState *ms = opaque;
        const char *buf = (void*)&ms->reg_mmio;

        if(addr > sizeof(ms->reg_mmio))
                return 0;
```

Since `max_access_size` is set to 4, one can read 4 bytes after the end of
`reg_mmio`. There we have lower 4 bytes of a pointer that is used for DMA
transfers:

```
        struct PCIMemoDevHdr reg_mmio;
        void *addr_ram;
```

This is an `mmap()`ped pointer, so this makes it possible to do arbitrary reads
and writes to other `mmap()`ped memory and to the shared libraries.

## Communicating with the device

The existing kernel module cannot trigger any of these issues. Writing one's
own for a kernel whose header files and config are not available, is a hassle.
However, as root, it's possible to do all this in userspace.

* PIO: use `ioperm()`, `inb()` and `outb()`.
* MMIO: it's mapped to the same physical address all the time, use `/dev/mem`.
* DMA: there is no IOMMU in this setup, DMA addresses are the same as physical
  addresses. Pick any page and use `/dev/mem`.

The protocol details can be copy-pasted from the kernel module verbatim.
Interrupt stuff can be ignored, because QEMU does everything synchronously.

Note: `/dev/mem` can be only used with `mmap()`. `read()` and `write()` don't
work - I wasted quite some time on this.

## Exploitation

Even though QEMU runs with the `-cpu kvm64` parameter, it still uses TCG for a
myriad of reasons:

* `/dev/kvm` is not passed to the container;
* There is no `kvm` group inside the container;
* QEMU is not given the `-accel kvm` parameter.

Since I had time, I thought it would be fun to target TCG in my exploit.

TCG organizes the code in translation blocks, which are linear chunks of guest
code translated to (almost) linear chunks of host code. Here are the relevant
structs:

```
struct tb_tc {
    const void *ptr;    /* pointer to the translated code */
    size_t size;
};

struct TranslationBlock {
[...]
    struct tb_tc tc;
```

`TranslationBlock`s and the corresponding translated code are placed in a
`code_gen_buffer`: a gigantic RWX mapping. In order to look up a
`TranslationBlock` by a translated code address, which is necessary among other
things for exception handling, `tb_tc`s are inserted into a tree, and the tree
is placed on the heap. Therefore, one finds a lot of `tb_tc`s on the heap.

It's quite predictable what a `tb_tc` looks like: an `mmap()`ped address
followed by a small-ish 64-bit integer. Translated code always starts with:

```
0x7f93e8bb5300:    mov    ebx,DWORD PTR [rbp-0x10]
0x7f93e8bb5303:    test   ebx,ebx
0x7f93e8bb5305:    jl     0x7f93e8bb54ec
```

which is needed for enforcing instruction count limits. In case of failure, it
goes to:

```
0x7f93e8bb54ec:    lea    rax,[rip+0xfffffffffffffd50]
0x7f93e8bb54f3:    jmp    0x7f93e8000018
```

The last address is very special and important: it's TCG prologue. QEMU
execution is driven by a C `translator_loop()`, which takes control when it's
no longer clear to the JITed code where to go next (i.e., if the upcoming
guest code is not yet translated). In order to pass control back to JITed code,
`translator_loop()` ultimately calls `tcg_qemu_tb_exec()`, which points to the
prologue.

So the prologue is executed very often. And is located in an RWX mapping. So
replacing it by shellcode immediately gives the host shell.

## Flag

`SECCON{q3mu_15_4_k1nd_0f_54ndb0x.....r1gh7?}`

[Nope](
https://qemu-project.gitlab.io/qemu/system/security.html#non-virtualization-use-case
). Not in this configuration, anyway.
