# Seccomp Hell

* Linux multi-stage pwn. We are given a VM image.
* Inspiration: https://hxp.io/blog/99/hxp-CTF-2022-one_byte-writeup/.
* Stage 1: userspace binary ROP.
  * Statically linked, no PIE.
  * Reads 256 bytes to stack.
  * In a slightly obfuscated way reads another 152 bytes to stack.
  * Closes all file descriptors.
  * Installs a seccomp filter that allows `read()`, `write()`, `open()`,
    `close()`, `mmap()`, `mprotect()`, `socket()`, `connect()`, `modify_ldt()`,
    `exit()` and `exit_group()`.
  * Triggers a ROP chain starting at the top of 152 bytes.
  * Goal: inject shellcode using a `socket()` + `connect()` + `mprotect()` +
    `read()` ROP chain.
  * We are talking to the binary via a PTY (injected using socat), which
    mangles all non-printable bytes.
    * `IEXTEN` is set for the PTY, so escape all bytes with `VLNEXT`. Append
      `VEOF` to flush the PTY buffers and make the binary see all the data.
  * 152 bytes are not enough to execute the whole chain.
    * Pivot to 256 bytes, which are located at smaller addresses, using ugly
      gadgets and observations about the initial register state. See
      `ROP_PIVOT` in the exploit for details.
  * 408 bytes are still not enough.
    * Mix a few parts of the shellcode chain into the pivot chain. Do not
      re-initialize registers that are preserved by gadgets.
* Stage 2: shellcode loader.
  * Writing shellcode in assembly is annoying.
    * Write it in C! See [`Makefile`](Makefile) and [`shellcode.lds`](
      shellcode.lds).
  * ROP can do only one `read()`. If the network connection is flaky, which it
    is, it will read only a part of shellcode.
    * Start with a very small shellcode loader, which does a `read()` loop.
    * Build shellcode stages in the reverse order, so that they know the size
      of what they are going to load.
* Stage 3: kernel backdoor.
  * There is a backdoor kernel module installed inside the VM.
  * Writing to the backdoor device creates a call gate with index 12 in the
    2nd LDT slot (`0xFFFF880000010000 + 96`).
    * `Documentation/arch/x86/x86_64/mm.rst` says:
      ```
      ffff880000000000 | -120    TB | ffff887fffffffff |  0.5 TB | LDT remap for PTI
      ``` 
    * ```
      commit f55f0501cbf65ec41cca5058513031b711730b1d
      Author: Andy Lutomirski <luto@kernel.org>
      Date:   Tue Dec 12 07:56:45 2017 -0800

          x86/pti: Put the LDT in its own PGD if PTI is on

          [...] an attack
          that can write the LDT is instant root due to call gates (thanks, AMD, for
          leaving call gates in AMD64 but designing them wrong so they're only useful
          for exploits) [...]
      ```
    * Goal: use the kernel backdoor to run kernel shellcode.
    * The system runs with `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION`.
    * When running in user mode, only kernel entry points, respective stacks,
      and a bit of other stuff is mapped.
    * What stuff? Among other things, an LDT (Local Descriptor Table).
    * To help with managing concurrency, there are two copies (slots) of it,
      which are used in turns. See `write_ldt()` for details.
    * Userspace may create custom local segments using the `modify_ldt()`
      system call. It may only create "boring" segments though.
    * An "exciting" segment would be a call gate. One can use a `call m16:64`
      instruction with call gate selector to set `%cs:%rip` to whatever the call
      gate descriptor specifies.
    * See Intel SDM Volume 3 Subsection 5.8.3 for details.
  * Create a "boring" descriptor with index 12, that, if interpreted as a call
    gate, will be accessible from userspace and transfer control to our kernel
    shellcode. In particular, make sure `%cs` is `0x10` and `dpl` is `3`. Since
    by default there is no LDT, it lands in the first slot.
  * The processor tracks LDT size, and now it's 13. However, 64-bit call gates
    consist of two descriptors, so if we try to use ours, we will get a
    General Protection Fault. Expand LDT to the maximum possible size by adding
    a descriptor with the maximum possible index `0x1fff`. Descriptor 13 will
    be all 0s, which is exactly what's needed. This will also move the LDT to
    the 2nd slot, which is required by the backdoor.
  * Trigger the backdoor. It will turn the "boring" descriptor into a call gate
    and replace its `%rip` with `0xc00000`.
  * Map kernel shellcode at this address.
  * An ugly binutils bug makes `gas` not emit a REX prefix for a 64-bit far
    call, which results in a 32-bit far call being emitted instead. Emit the
    REX prefix manually.
* Stage 4: kernel entry.
  * The kernel shellcode starts in a limbo state.
  * Goal: stabilize the execution environment.
  * The kernel does not use call gates, and its interrupt handlers were not
    written with call gates in mind. Seeing an interrupt happening in the limbo
    state will confuse any of them, resulting in a stack overflow.
    * Turn off interrupts.
  * We still don't know where the kernel is.
    * The `MSR_LSTAR` register holds the address of kernel's
      `entry_SYSCALL_64`. Read it and compute the kernel base.
  * The page we are running from is a user page. Fortunately, SMEP is off.
  * But SMAP is still on. Reading or writing any data will cause an exception.
    * Disable it in `%cr4`.
  * The CPU has already taken care of switching `%ss:%rsp` to the values
    specified in TSS. Since this is also used for other inter-privilege control
    transfers, the new values are sane.
  * The page we are running from is referenced by multiple page tables. The
    respective kernel page table has the execute-disable bit set. This means we
    cannot switch to kernel page tables yet.
    * Copy ourselves to a kernel page.
      * Kernel entry pages are mapped, but are write-protected.
      * Turn off write protection in `%cr0`.
      * Use a big `0xcc`-filled block after `entry_SYSCALL_64` as destination.
      * The compiler will generate `rep movs` for the copy, which requires
        proper values in `%ds` and `%es`. Load `0x18` into both.
    * Call the copy.
    * Switch to kernel page tables. This is done by ANDing the current value of
      `%cr3` with a specific mask - exactly like the kernel itself does it.
  * We need to access percpu variables.
    * The kernel does this using the `%gs` register.
    * But `IA32_GS_BASE` has a value for userspace execution.
    * Use the `swapgs` instruction to swap it with `IA32_KERNEL_GS_BASE`.
* Stage 5: privilege escalation.
  * Goal: remove seccomp and gain root.
  * Since write protection is off anyway, patch the `__secure_computing()`
    function to return `0` immediately.
    * A smarter approach would be to clear the `SYSCALL_WORK_SECCOMP` flag.
  * `current->cred = current->real_cred = init_cred` messes up the reference
    counting.
    * Resort to setting all ids in `cred` to `0`.
* Stage 6: resuming userspace.
  * Undo what we did during entry.
    * Restore `%gs`, `%cr0`, `%cr3`, `%cr4`, `%ds` and `%es`.
    * Setting the interrupt flag may result in the immediate delivery of the
      pending interrupts, causing a stack overflow.
      * Return and set the interrupt flag atomically using the `iretq`
        instruction.
* Stage 7: getting a shell.
  * `socat` will send us a `SIGTERM` in roughly 0.4 seconds.
    * I figured this out using [initramfs-wrap](
      https://github.com/mephi42/initramfs-wrap) and
      `strace -ttt -f /sbin/chroot /orig /init`.
    * Now that we can use syscalls again, set the signal mask to ignore all
      signals.
  * Duplicate or ROP-provided socket descriptor `0` to `1` and `2`.
  * `execve("/bin/sh")`.
  * Wander the file system aimlessly.
    * The instance times out way faster than the promised 3 minutes.
    * `/root/flag.txt`
      * "please get a full root shell"
        * ???
          * statement dreamed up by the utterly deranged
            * they have played us for absolute fools
    * The flag printer is in
      `/root/.flag_is_not_here/.flag_is_definitely_not_here/.genflag`.
* Conclusion.
  * Troll challenge.
    * It's exactly what it says on the tin, so nobody has a right to complain.
  * The core idea is still a fun one.
