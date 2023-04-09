# runeme (mini writeup)

* brainfuck with a fancy encoding. The meaning of the encoding changes based on
  values in memory.
* Fortunately each operator still has a single meaning, which can be extracted
  by tracing. As a result we get a normal brainfuck program. About 25% of code
  is not covered though, but 75% is more than enough to look at for now.
* Failed attempt 1: use [symbolic execution](solveit_fail.py). The nature of
  brainfuck is such that there are too many control dependencies, which a
  primitive symbolic executor has problems seeing through.
* Failed attempt 2: transpile to C and let libFuzzer/AFL/SymCC figure it out.
  Basically same problem as above: control dependencies are killing these
  fuzzers.
* Failed attempt 3: compile the resulting C with optimizations and open the
  result in binja. Both gcc and clang actually do a good job seeing through
  control dependencies, but unfortunately that's still not enough to produce
  something readable.
* Failed attempt 4: optimize some loops and sequences with a script and only
  then use gcc/clang. The readability improves, but it's still not enough.
* Successful strategy: let a smarter teammate read the code as is without any
  fancy tooling. Turns out the code checks the inputs byte by byte and
  increments a counter at the end of RAM for each failed comparison.
  * So just brute force it symbol by symbol. The input is not a flag, but a
    password. Upon entering the correct password, the remaining 25% of code is
    run - it prints the flag.
