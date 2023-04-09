# traz (mini writeup)

* No files are given. The remote server allows loading a program for an unknown
  architecture and run it.
* Probing for 1-byte instructions returns a number of various error messages:
  * `SIGSEGV detected`
  * `invalid instruction detected`
  * `invalid register detected`
  * For opcode `0x40` there appears `-------- [DEBUG] --------` output, which
    shows that there are 6 8-byte registers (`A`, `B`, `C`, `D`, `F`, `PC`) and
    256 bytes of data RAM. The code is not in RAM.
  * Opcode `0xff` causes the program to exit without any output.
* Probing for 2-byte instructions doesn't add much.
* Probing for 3-byte instructions adds the following into the mix:
  * `invalid syscall detected`
  * `sys_open() -> "" does not exist`
  * `sys_read() -> 0 is not a valid length`
  * `sys_sendfile() -> cannot send 0 to itself`
  * `sys_write() -> 0 is not a valid length`
* Playing with the debug opcode `0x40`, one can see the following pattern:
  ```
  40:           SIGSEGV detected at 0xff
  4040:         SIGSEGV detected at 0xff
  404040:       invalid instruction detected at 0x01
  40404040:     SIGSEGV detected at 0xff
  4040404040:   SIGSEGV detected at 0xff
  404040404040: invalid instruction detected at 0x02
  ```
  This clearly shows that instructions are 3 bytes long, and that PC contains
  the instruction index (and not byte index).
* All syscall-related errors come from opcode `0x80`. One can clearly see that
  the third byte is an opcode number:
  * `0x01` is `sys_open()`
  * `0x02` is `sys_read()`
  * `0x04` is `sys_write()`
  * `0x08` is `sys_sendfile()`
  * `0x10` is `sys_close()`
* Looking at opcode-related errors, one can see that the valid opcodes are:
  `0x00`, `0x01`, `0x02`, `0x04`, `0x08`, `0x10`, `0x20`, `0x40`, `0x80` and
  `0xff`.
* Looking at register-related errors from opcode `0x01`, one can see that the
  valid register encodings are `0x01`, `0x02`, `0x04`, `0x08`, `0x10` and
  `0x20`.
* Furthermore, combining debugging opcode `0x40` with opcode `0x01` makes it
  clear that this is a "move immediate" instruction; the immediate is stored in
  its second byte.
* This allows loading initial values into registers and playing with the other
  opcodes. They appear to be: addition, load byte, store byte, comparison,
  and conditional jump.
* syscalls arguments are passed via `A` and `B`. The result is stored in a
  register specified in the second byte.
* We can now write `sendfile(1, open("flag"))`. It works, but it's a fake flag.
* We can also download the service binary: `/proc/self/exe`.
* The service is initialized by `mmap()`ing and running a `boot.bin` file, so
  download it too.
* Opcode `0x00` can read arbitrary code from a given file descriptor into the
  `boot.bin` page and restart the service, but only if a magic flag is set.
  Doing this clears the magic flag. Since this sequence is performed during
  initialization, the service runs with the magic flag cleared.
* Opcode `0x00` can also print an error with a given code. If it's a known
  error, it also terminates the service, otherwise it does nothing. For
  whatever reason it restores the magic flag.
* So run `0x00` with a non-existent error, load shellcode into `boot.bin` and
  restart the service.
