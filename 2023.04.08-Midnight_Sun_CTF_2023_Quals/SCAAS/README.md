# SCAAS (mini writeup)

* No files are given, but the service lets the user download its binary.
* It's an x86 (32-bit) linux binary.
* The service asks for three passwords - angr can deal with that just fine.
* It then lets the user run alphanumeric shellcode (mapped as `rwx`).
* The registers are not cleared, so one can find some interesting values here
  and there. In particular, the stack is available, and the shellcode address
  is in `eax`.
* There are examples of alphanumeric shellcode on the Internet, but they rely
  on executable stack. In particular, they synthesise the non-alphanumeric
  `int 0x80` syscall instruction on stack. In this challenge we are still
  `rwx`, but are not running from stack.
* So that's the only thing that needs tweaking here. The alphanumeric
  `xor dword ptr [eax], esi` instruction allows us to xor our code with a
  register. The rest works as is.
