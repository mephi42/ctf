# pprofile (mini writeup)

* A kernel module that allows adding, deleting and querying "notes" by name.
* Bug: querying does not check whether the output pointer is a userspace
  address.
* Brute force 19 bits of KASLR entropy by trying to write into the beginning of
  the kernel's rw data section.
* The query code writes 3 ints: `p[0] = 0; p[2] = pid; p[3] = len;`. Note that
  `p[1]` is left as is.
* `0` and `len` are tricky to use, but we can perfectly control the lowest
  bytes of `pid`. Using multiple overlapping writes, we can create bigger
  values.
* Let's [write into `modprobe_path`](
  https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)!
  It can be done in 4 steps:
  * `????????/sbin/modprobe` - the initial contents of `modprobe_path - 8`. 
  * `?0000???/t???????probe` - make `pid` end with `t`, write into
    `modprobe_path - 7`.
  * `?00000??/tm???????robe` - make `pid` end with `m`, write into
    `modprobe_path - 6`.
  * `?000000?/tmp???????obe` - make `pid` end with `p`, write into
    `modprobe_path - 5`.
  * `?000000?/tmp/10?????be` - make `pid` end with `/\x01\x00`, write into
    `modprobe_path - 4` (this one can take a while).
* Put a flag stealing binary into `/tmp/\x01`.
* `exec()` a malformed binary.
