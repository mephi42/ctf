# dROP Baby (mini writeup)

* The challenge contains a RISC-V binary without a config. Config is important,
  because it contains message sizes. Each message must end with a valid CRC.
* Request a config from the server. The respective message size is unknown, so
  generate a message that fits multiple sizes: start with the smallest one, and
  keep appending CRCs.
* The configured size for B2 message is larger than the allocated stack buffer.
  This means ROP.
* Flag is initially in an environment variable. Even though it's
  `unsetenv()`ed, the value remains on stack.
* The argument registers in RISC-V ABI are not callee-saved. Therefore, the
  gadgets are a bit more complicated than on x86_64.
  * Goal: `write(1, &FLAG - not_too_much, a_bit_more)`.
  * Gadget 1 (epilogue): pop RA and callee-saved registers; jump to RA.
    Useful for initial loading of values.
  * Gadget 2 (function pointer call): copy callee-saved registers to argument
    registers, jump to a callee-saved register.
  * Chaining these two gadgets allows calling a single function.
    This is enough to achieve the goal.
  * Since we don't have a stack leak, we need a variation of gadget 2 that
    loads a stack-relative address into the second argument
    (`c.addi4spn a1, sp, 0x10`).
