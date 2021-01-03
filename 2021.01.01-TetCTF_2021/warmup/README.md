# warmup - mini writeup

* Bug 1: `printf(player_name)`.
* Bug 2: glibc `TYPE_3` RNG is used with a 3-byte seed. We can just bruteforce
  it and win any amount of money we want.
* Leak all the addresses we want.
* Use `%n` to overwrite the LSB of pointer to money, so that it points to the
  feedback address instead.
* Play 1 round and recover the RNG seed.
* Play another round and bet a very specific amount of money, so that the
  feedback address is changed to the address of the return address.
* Enter one_gadget address as feedback.
