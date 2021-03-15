# nasm_kit (mini writeup)

* Send a blob to the server, it will be emulated as x86_64 code in unicorn.
* The following syscalls are forwarded to the host OS:
  * `read`
  * `write`
  * `mmap`
  * `munmap`
  * `exit` / `exit_group`
* Any interrupt terminates the interpreter.
* Bug: `mmap` and `munmap` are forwarded without any checks whatsoever.
* Use the binary search to find the binary in the `ELF_ET_DYN_BASE` ..
  `ELF_ET_DYN_BASE + (1 << (CONFIG_ARCH_MMAP_RND_BITS + PAGE_SHIFT))` range
  using the `MAP_FIXED_NOREPLACE` flag.
* Map the shellcode over the third page of the binary using the `MAP_FIXED`
  flag.
  * This page contains code. 
  * Replacing it not-so-carefully will not crash the binary right away.
  * It will mess up `syscall_abi` array though, so no further syscalls after
    this. Repairing `syscall_abi` is possible, but not necessary.
* Trigger an interrupt to terminate the interpreter, this will execute the
  shellcode.
