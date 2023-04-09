# SPD D (mini writeup)

* Kernel pwn speedrun. SMAP and SMEP are off.
* The vulnerable module provides stack OOB read and write.
* Leak the kernel base using the OOB read.
* Jump to the shellcode in userspace using the OOB write.
* Call `commit_creds(prepare_kernel_cred(0))`.
* Manually switch back to userspace. Spawn a shell.
