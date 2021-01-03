# babyformat (mini writeup)

* Bug: we can `fprintf()` anything to `/dev/null`. The binary is built without
  `-fPIE` and the format string is read into `.bss`.
* Chain `%n`s like in hxp CTF 2020's still-printf.
  * Chaining works until a positional specifier (`$`) is encountered.
  * Saved frame pointers on stack form a chain. Use frame pointer #1 in order
    to overwrite the LSB of frame pointer #2, so that it points to the return
    address.
  * Use frame pointer #2 in order to overwrite the LSW of the return address,
    so that it points to a `leave; ret` (stack pivot) gadget.
  * Use frame pointer #1 again (this time through `$`, because we don't need to
    chain `%n`s anymore) in order to put the ROP chain address into frame
    pointer #2.
* Put the ROP chain at the end of the format string.
  * `puts@PLT(&puts@GOT)` in order to leak libc address.
  * Read it from the exploit, compute a one_gadget address and send it back to
    the ROP chain.
  * `read()` one_gadget address into the last slot of the ROP chain.
