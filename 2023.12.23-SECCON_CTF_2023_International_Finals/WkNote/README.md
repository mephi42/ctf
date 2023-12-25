# WkNote (mini writeup)

* Windows kernel module pwn.
* Install the environment using `vagrant up`.
  * If Vagrant dies with a backtrace, chances are, some Vagrant plugin is
    missing. Fix with, e.g., `vagrant plugin install winrm`.
* I tried WinDbg remote kernel debugging at Midnight Sun CTF 2023 Finals, where
  it was constantly losing the connection - and reconnecting was not possible
  without a reboot. So use it only for `MEMORY.DMP` analysis.
* Enable the [VirtualBox GDB stub](
  https://sysprogs.com/VisualKernel/documentation/vboxdev/).
  * Eventually get depressed due to bad performance: each command takes at
    least one second, and bad stability: countless spurious `SIGTRAP`s.
* Switch to libvirt.
  * The [challenge box](
    https://app.vagrantup.com/gusztavvargadr/boxes/windows-11-23h2-enterprise)
    does not support the libvirt provider.
  * `qemu-img convert -O qcow2` the image created by Vagrant after it boots at
    least once. Converting and booting the image from the freshly downloaded
    box fails with `Windows installation cannot proceed`.
  * Create a VM from the converted image using `virt-manager`.
  * Turn off Secure Boot, which prevents loading the challenge driver.
    * There is no "Secure Boot" checkbox in libvirt.
    * `virsh edit win11`.
    * ```xml
      <os>
        <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
        <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.ms.fd</loader>
        <nvram template='/usr/share/OVMF/OVMF_VARS.fd'>/var/lib/libvirt/qemu/nvram/win11_VARS.ms.fd</nvram>
        <boot dev='hd'/>
      </os>
      ```
  * Allow loading the challenge driver: `bcdedit /set testsigning on`. This is
    already in the `Vagrantfile`, but NVRAM is lost after conversion, so this
    needs to be done again manually.
* Enable the GDB stub:
  ```xml
  <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    <!-- ... -->
    <qemu:commandline>
      <qemu:arg value='-s'/>
    </qemu:commandline>
  </domain>
  ```
* SSH is already configured by Vagrant and can be [used right away](
  Makefile#L4).
* [Cross-compile](Makefile#L13) the exploit using `x86_64-w64-mingw32-gcc`.
* [`scp` the kernel](Makefile#L16) and load it into the favorite decompiler.
* Attaching the debugger will most likely interrupt the kernel at
  `HalProcessorIdle`. From this [calculate the kernel base](gdbscript#L6) for
  debugging.
* [Iterate over modules](gdbscript#L13) starting from `PsLoadedModuleList`
  until we find the challenge module. Set a number of [breakpoints](
  gdbscript#L33).
* Each file object manages a number of buffers and associated metadata:
  ```c
  typedef struct NoteEnt {
      PCHAR Buf;
      ULONG nSpace, nWritten;
  } NOTE_ENT, *PNOTE_ENT;

  typedef struct NoteRoot {
        NOTE_ENT Entry[MAX_ENT];
        KMUTEX   Lock;
  } NOTE_ROOT, *PNOTE_ROOT;
  ```
* The exploit can allocate, write, read and free the buffers.
* Bug: `NOTE_ENT.Buf` is not initialized. However, `NOTE_ENT.nSpace` is set to
  `SPACE_FREED`.
* Bug: the read function does not check `NOTE_ENT.nSpace`.
* Bug: the free function does not check `NOTE_ENT.nSpace`.
* End result: the exploit can cause a double free.
* `whoami /all` indicates that the exploit runs with the medium integrity
  level.
* Obtain the kernel base [using
  `NtQuerySystemInformation(SystemModuleInformation)`](
  https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo
  ).
* The kernel allocator does not exhibit LIFO behavior, so we need to [spray the
  kernel heap](pwnit.c#L208). Open the device multiple times, writing forged
  `NOTE_ROOT`s that point to the kernel base into the 3rd buffers. Then close
  all the file objects.
* Open the device multiple times [again](pwnit.c#L226). For each file object,
  allocate `0xfff - i` bytes for the 2nd buffer, where `i` is the index of the
  file object. The goal is to have a predictable value in `nSpace`.
* [Read](pwnit.c#L241) from all 3rd buffers.
  * If the result is `MZ`, which corresponds to the data located at the kernel
    base, then the corresponding `NOTE_ROOT` is allocated on top of a forged
    one. In this case, allocate the 3rd buffer to avoid crashes.
  * If the result's `j = 0xfff - nSpace` is sane, then we found an opened
    `NOTE_ROOT` (`i`) that points to a different opened `NOTE_ROOT` (`j`).
* [Free](pwnit.c#L265) the 3rd buffer of `i`. This will free the `j`'s
  `NOTE_ROOT`.
* Allocate more `NOTE_ROOT`-sized buffers. One of them will overlap with the
  `j`'s `NOTE_ROOT`.
* Write a forged `NOTE_ROOT` into all of them, effectively setting `j` to
  whatever we want. Note: we need to preserve the `KMUTEX` value, otherwise
  the kernel will crash when trying to lock it.
* Arbitrary read/write is achieved by setting a forged `NOTE_ENT.Buf` and then
  reading from or writing to `i`.
* [Read](pwnit.c#L285) `PsInitialSystemProcess` and its `Token`, which
  corresponds to essentially a root user.
* Loop over its `ProcessListEntry` until `ImageFileName` matches that of the
  exploit process.
* Overwrite the `Token` and spawn `cmd.exe`.
* `SECCON{ExAllocatePoolWithTag_pr0v1d35_un1n1714l1z3d_m3m0ry}`.
