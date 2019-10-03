## Reverse Engineering - Fat Module

We are given x86 and arm virtual machine images. x86 is more familiar - let's
start with it:

```
x86$ sudo apt install qemu-system
x86$ sudo ./run.sh
[    0.000000] Linux version 5.1.16 (user@host) (gcc version 7.4.0 (Buildroot 2019.05.1-gb18f532-dirty)) #1 SMP Mon Sep 2 14:14:04 EEST 2019
Welcome
none login: root
#
```

Nice, we can login as `root` without a password - no need to hack the image.
Ditto the arm one:

```
arm$ sudo ./run.sh
Linux version 5.1.16 (user@host) (gcc version 7.4.0 (Buildroot 2019.05.1-gaed32c5-dirty)) #1 Mon Sep 2 14:36:22 EEST 2019
Welcome
none login: root
#
```

That took a while compared to x86 (no KVM, TCG all the way), but the image
seems to work as well. Now let's implement the module - quick googling gives us
[an inspiration](
https://gist.github.com/brenns10/65d1ee6bb8419f96d2ae693eb7a66cc0).

Instead of manually messing with cross-compilers, let's just take buildroot:

```
FatModule$ git clone git@github.com:buildroot/buildroot.git
buildroot$ git worktree add ../buildroot-x86 2019.05.1
buildroot$ cp ../x86/linux_x86_config ../buildroot-x86
buildroot$ git worktree add ../buildroot-arm 2019.05.1
buildroot$ cp ../arm/linux_arm_config ../buildroot-arm
```

Let's build the x86 one:

```
buildroot-x86$ make menuconfig
BR2_x86_64=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="5.1.16"
BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="linux_x86_config"
buildroot-x86$ make -j$(getconf _NPROCESSORS_ONLN)
```

and the arm one:

```
buildroot-arm$ make menuconfig
BR2_arm=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="5.1.16"
BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="linux_arm_config"
buildroot-arm$ make -j$(getconf _NPROCESSORS_ONLN)
```

This is going to take a while. In the meantime, let's try reversing the kernel.
First, extract and uncompress vmlinux (ELF image) from bzImage (bootable image).
There is a [script](
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/scripts/extract-vmlinux
) for this in the kernel source tree:

```
x86$ ./extract-vmlinux bzImage >vmlinux
```

vmlinux can be loaded into IDA. Module-related stuff lives in
[`kernel/module.c`](
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/module.c?h=v5.1.16
) - in particular, we are interested in `load_module()` and
`elf_header_check()`. Let's locate the latter by looking for comparisons with
the ELF signature `\x7FELF`:

```
IDA$ Alt+B
Binary Search$ 7F 45 4C 46
```

There are about 10 entries, but only one is close to the beginning of a
function. Let's reverse it a little bit:

```
.text:FFFFFFFF810DFF40 load_module     proc near

...

.text:FFFFFFFF810DFF66                 cmp     [rdi+load_info.len], (size Elf_Ehdr) - 1

...

.text:FFFFFFFF810DFF7C                 jbe     return_enoexec
```

This is supposed to be

```
	if (info->len < sizeof(*(info->hdr)))
		return -ENOEXEC;
```

but `load_info.len` is at offset `0x20`, while it [should be at `0x18`](
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/module-internal.h?h=v5.1.16#n20
):

```
struct load_info {
	const char *name;
	/* pointer to module in temporary copy, freed at end of load_module() */
	struct module *mod;
	Elf_Ehdr *hdr;
	unsigned long len;
```

Is there a new field? We'll see.

```
.text:FFFFFFFF810DFF82                 cmp     [r14+Elf_Ehdr.e_machine], EM_PWNTHYBYTES
.text:FFFFFFFF810DFF89                 jz      em_is_pwnthybytes
.text:FFFFFFFF810DFF8F again:
```

Hey, new machine type `0xE6`! It does not match [any of the existing ones](
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/elf-em.h?h=v5.1.16#n6
). How is it handled? Let's find out:

```
.text:FFFFFFFF810E0154 em_is_pwnthybytes:
.text:FFFFFFFF810E0154                 lea     rax, [r14+(size Elf_Ehdr)]
.text:FFFFFFFF810E0158                 lea     rdx, [r14+180h]
.text:FFFFFFFF810E015F                 jmp     short em_is_pwnthybytes_cont
.text:FFFFFFFF810E0161
.text:FFFFFFFF810E0161 find_0x3e_loop:
.text:FFFFFFFF810E0161                 add     rax, size pwn_header
.text:FFFFFFFF810E0165                 cmp     rdx, rax
.text:FFFFFFFF810E0168                 jz      short return_enoexec
.text:FFFFFFFF810E016A
.text:FFFFFFFF810E016A em_is_pwnthybytes_cont:
.text:FFFFFFFF810E016A                 cmp     [rax+pwn_header.magic], 3Eh ; '>'
.text:FFFFFFFF810E016D                 jnz     short find_0x3e_loop
.text:FFFFFFFF810E016F                 mov     [r15+load_info.pwn_header], r14
.text:FFFFFFFF810E0173                 add     r14, [rax+pwn_header.elf_offset]
.text:FFFFFFFF810E0177                 mov     [r15+load_info.hdr], r14
.text:FFFFFFFF810E017B                 mov     rax, [rax+pwn_header.elf_size]
.text:FFFFFFFF810E017F                 mov     [r15+load_info.len], rax
.text:FFFFFFFF810E0183                 jmp     again
```

So, between offsets `0x40` (right after the normal ELF header) and `0x180` we
now have 16 entries with the following format:

```
00000000 pwn_header      struc
00000000 magic           dd ?
00000004 elf_offset      dq ?
0000000C elf_size        dq ?
00000014 pwn_header      ends
```

The loop tries to find the array entry with the magic value and saves the
pointer to it into the new `load_info.pwn_header` field.

In x86 kernel, `magic` appears to be `0x3E`, which corresponds to the existing
`EM_X86_64`. No obfuscation - long live best coding practices! Keep Linus happy!
Also let's pray that ARM counterpart is simply `EM_ARM` so that we wouldn't have
to reverse the ARM kernel.

The rest of the module loading flow appears to be unmodified. So we need to
build and concatenate x86 and arm versions of the module, prepend ELF and PWN
headers, nd the result should just work (TM).

The kernels have finished building, let's compile the stolen code:

```
FatModule$ cat >Makefile
obj-m += mod.o

x86:
	make -C $(PWD)/buildroot-x86/output/build/linux-5.1.16 M=$(PWD)

arm:
	PATH=$(PWD)/buildroot-arm/output/host/bin:$$PATH make -C $(PWD)/buildroot-arm/output/build/linux-5.1.16 ARCH=arm CROSS_COMPILE=arm-buildroot-linux-uclibcgnueabi- M=$(PWD)
^D
FatModule$ make x86
FatModule$ mv mod.ko mod-x86.ko
FatModule$ make arm
FatModule$ mv mod.ko mod-arm.ko
```

Squash 'em:

```
FatModule$ cat >script
#!/usr/bin/env python3
import struct

x86_blob = open('mod-x86.ko', 'rb').read()
arm_blob = open('mod-arm.ko', 'rb').read()
master = b'\x7FELF' + b'\x00' * 14 + b'\xE6\x00' + b'\x00' * 0x2c
x86 = struct.pack('<IQQ', 0x3e, 0x180, len(x86_blob))
arm = struct.pack('<IQQ', 0x28, 0x180 + len(x86_blob), len(arm_blob))
others = b'\0' * (0x14 * 14)
open('fat.ko', 'wb').write(master + x86 + arm + others + x86_blob + arm_blob)
^D
FatModule$ python3 script
```

Let's test whether this works... Oh, wait, how to copy this file into guests?
We'll need to configure the networking and use [py3tftp](
https://pypi.org/project/py3tftp/), which is great because it requires zero
configuration:

```
FatModule$ sudo tunctl -u $USER -t tap0
FatModule$ sudo ifconfig tap0 192.168.100.1 up
FatModule$ py3tftp &
2019-10-02 22:37:52,677 [INFO] Starting TFTP server on 0.0.0.0:9069
```

Now test on x86:

```
FatModule$ vim x86/run.sh
Append
-netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no -device e1000,netdev=mynet0,mac=52:55:00:d1:55:01
to qemu-system-x86_64 invocation.
FatModule$ cd x86
x86$ sudo ./run.sh
# ifconfig eth0 192.168.100.2 up
# tftp 192.168.100.1 9069 -gr fat.ko
# insmod fat.ko
# mknod foo c 400 0
# cat foo
Hello, World!
```

Cool! ARM works too, so our guess regarding `EM_ARM` was right. Let's submit:

```
FatModule$ cat >submit
#!/usr/bin/env python3
import struct
import sys

f=open('fat.ko', 'rb').read()
sys.stdout.buffer.write(struct.pack('<I', len(f)))
sys.stdout.buffer.write(f)
^D
FatModule$ python3 submit | nc 137.117.216.128 13376
```

And the flag is ours!
