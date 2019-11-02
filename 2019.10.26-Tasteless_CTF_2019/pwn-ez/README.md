# Pwn - ez

We are given a `.c` file and a corresponding binary compiled for FreeBSD 12.0:

```
$ file ez
ez: ELF 64-bit LSB executable, x86-64, version 1 (FreeBSD), dynamically linked, interpreter /libexec/ld-elf.so.1, for FreeBSD 12.0 (1200086), FreeBSD-style, with debug_info, not stripped
```

In anticipation of debugging, let's set up a virtual machine:

* Download the official [FreeBSD-12.0-RELEASE-amd64.qcow2.xz](
https://download.freebsd.org/ftp/releases/VM-IMAGES/12.0-RELEASE/amd64/Latest/FreeBSD-12.0-RELEASE-amd64.qcow2.xz
)
* Start, configure and ssh into it by following [the instructions from QEMU wiki](
https://wiki.qemu.org/Hosts/BSD
)
* `host$ scp -P 7722 root@localhost ez:`
* `guest# pkg install bash gdb netcat`
* `guest# /bin/bash`
* `guest# rm -f /tmp/f && mkfifo /tmp/f && cat /tmp/f | (./ez; echo $? >&2) | nc -l 10801 > /tmp/f`

The challenge consists of three phases:

* Read 5-byte x86_64 shellcode from stdin and run it (all registers are set to
  0, but there is a dynamically generated return sequence, so no need to worry
  about that).
* Print addresses of `system` and stack.
* Read an arbitrary amount of data from stdin into a stack buffer.

x86_64 FreeBSD follows the [same ABI](
https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
) as Linux, and [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) handles
FreeBSD binaries just fine, so writing a ROP to call `system("/bin/sh")` is not
a big deal. But how to defeat the stack protector?

```
  400da0:       55                      push   %rbp
  400da1:       48 89 e5                mov    %rsp,%rbp
  400da4:       48 83 ec 40             sub    $0x40,%rsp
  400da8:       64 48 8b 04 25 00 00    mov    %fs:0x0,%rax
  400daf:       00 00
  400db1:       48 89 45 f8             mov    %rax,-0x8(%rbp)
  400db5:       31 c0                   xor    %eax,%eax
```
```
  401098:       64 48 33 0c 25 00 00    xor    %fs:0x0,%rcx
  40109f:       00 00
  4010a1:       74 05                   je     4010a8 <main+0x308>
  4010a3:       e8 18 f8 ff ff          callq  4008c0 <__stack_chk_fail@plt>
  4010a8:       c9                      leaveq
  4010a9:       c3                      retq
```

Apparently FreeBSD stores the 64-bit cookie at `%fs:0x0`. Ideally we should use
the shellcode to write it to stdout, but there appears to be no way to fit that
in a 5-byte sequence, especially since all the registers (except `%rax`, which
points to the shellcode) are cleared. How about overwriting it?

That doesn't seem to fit either:

```
64 c7 04 25 00 00 00 00 00 00 00 00     movl $0, %fs:0x0
```

12 bytes! However, 8 of those bytes are an immediate address and an immediate
value. What if we do exactly the same, but use registers instead? They are all
0s after all:

```
64 48 21 00                             andq %rbx, %fs:(%rbx)
```

Just 4 bytes, so let'just add a nop and get the flag:
`tctf{s3tt1n9_fsgsb4s3_fr0m_lu5ersp4c3_wh4t_c0uld_g0_wr0ng?}`. This explains why
the shellcode buffer is 5 bytes long: the intended solution was to use `wrfsbase
%rax`.
