# brohammer (mini writeup)

* A single bitflip in the kernel RW memory is allowed.
* [Extract kallsyms](https://github.com/mephi42/ida-kallsyms).
* [Attach with gdb](https://qemu-project.gitlab.io/qemu/system/gdb.html), put a
  breakpoint on [`bprm_fill_uid`](
  https://elixir.bootlin.com/linux/v4.17/source/fs/exec.c#L1509).
* Run `/bin/iconv`, dump `bprm->file->f_path.dentry->d_inode`. Since the
  challenge uses initramfs, `CONFIG_SMP` is disabled and `nokaslr` is
  specified, the inode addresses are extremely stable.
* Flip `inode->i_mode ^= S_ISUID`, run `/bin/iconv /root/flag`.
* Other possibilities, that were tried, but didn't work:
  * Setting the setuid bit on `busybox`. While this works, busybox [drops
    privileges](
    https://git.busybox.net/busybox/tree/libbb/appletlib.c?h=1_33_stable#n682)
    on startup.
  * Creating a lot of small flag reading binaries (spraying) and randomly
    flipping `inode->i_mode ^= S_ISUID` on one of them. While this works,
    it's not possible to create a `root`-owned binary, so the setuid bit
    obtained this way is useless.
  * Flipping a bit in IDT with the goal to have an interrupt handler in
    userspace. Not possible, since the canonical kernel addresses start with
    `ffff` and the canonical userspace addresses start with `0000`.
  * Flipping a bit in [`user_addr_max()`](
    https://elixir.bootlin.com/linux/v4.17/source/arch/x86/include/asm/uaccess.h#L39
    ) with the goal of confusing `copy_from_user()` / `copy_to_user()`. Not
    possible for the same reason.
  * Flipping a bit in a global function pointer, which is normally `NULL`,
    with the goal to have it point to userspace. No such pointers were located.
  * Flipping a bit in a global length variable bound to a `/proc` or `/sys`
    file (e.g. `/sys/kernel/boot_params/data`), with the goal of dumping all
    memory using that file (since initramfs is used, the flag is in the kernel
    memory). Unfortunately all such variables are either copied to the heap
    during initialization or are marked as `__ro_after_init` (gj, Kees! xD).
  * [Flipping a bit in a page table](
    https://hxp.io/blog/82/Midnightsun-CTF-2021-Brohammer/). This is the
    correct solution, but one has to look into the physmap. I looked only into
    the kernel text, and there a single bit flip was not enough.
