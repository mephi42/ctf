# CST (mini writeup)

* The program builds Clang AST and converts it into its own representation.
  * The goal is to give it a `.c` file and read `/flag`.
  * The `#` sign is prohibited. Digraphs and trigraphs are off.
  * There is no interactivity, one can only submit a file.
  * The binary is loaded at a fixed address. RELRO is off.
* The program creates nodes for functions and various statements.
  * By adding calls like `annotation("abc")` and `type("def")` inside blocks,
    it's possible to associate the respective strings with them.
  * Annotations are stored in `char [64]` (filled with `strcpy()`, protected by
    a length check) and types are stored in `std::string` (no longer than 18
    bytes) that immediately follows it.
* Bug: the annotation length check is flawed, since it looks for the next `"`
  without considering escaping. So it thinks `"\"AAA"` is only 3 bytes, but
  copies all 7.
  * Arbitrary write is achieved by overflowing the annotation into the type's
    `std::string` pointer with the target address, and then calling `type()`
    with the desired value.
  * Since `strcpy()` stops at the first zero, call `annotation()` multiple
    times: first with all zeros changed to `A`, then all except the last one,
    and so on.
  * Both `type()` and `annotation()` preserve binary zeros and non-printable
    characters. One only has to make sure that `\n` and `"` do not appear,
    since they break string literals.
* A worthy goal is to call `main(..., ["prog", "/flag"])`. This will print the
  flag in the Clang error message.
* There don't seem to be any good gadgets or GOT targets.
  * ret2csu is gone.
  * No stack pivot gadgets.
  * No useful functions like `system()` or `execve()`.
* There is a global `functionList` variable, which contains function nodes.
  * Overwrite it with a fake vector containing two fake nodes.
  * The first node is the "bomb" node. Its purpose is to stop the infinite
    recursion, since the server does not copy the program output on timeouts.
    * Leave all fields at 0, in the fake vtable set the pointer to the `dump()`
      method to `getpid()`, essentially making it a no-op.
    * Fake the heap chunk headers around the node itself, making it possible
      to `free()` it once on the original `main()` invocation, but making the
      program crash due to double free on the second invocation.
  * The second node is the "flag" node. Its purpose is to call `main()` with
    the controlled arguments.
    * In the fake vtable, set the pointer to the `dump()` method to a gadget
      that loads `rsi` and jump address from memory pointed to by `rdi` (which
      points to the "flag" node itself).
    * Make `rsi` point to fake argv.
    * Use the second instruction of `main()` as a jump address. Jumping to
      `main()` itself causes the stack to become misaligned, which is fixed by
      skipping the first `push %rbp`.
* The server's pipe is clogged by clang diagnostics, so it hangs. The
  diagnostics are emitted, because string literals contain unprintable and NUL
  characters. Make it less verbose by putting everything on one line.
