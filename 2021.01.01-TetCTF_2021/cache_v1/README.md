# cache_v1 (mini writeup)

* Bug: instead of using `caches[key]`, the code uses `caches[hash(key)]`.
* libstdc++ hashes strings with MurmurHash. Copy the logic to Python and use z3
  in order to generate a collision.
* seccomp allows only `mmap()`, `open()`, `read()`, `write()` and `close()`, so
  one_gadget is unusable.
* Create a victim cache of size 1, then write into it. This will allocate a
  buffer of size 1.
* Create another cache with a colliding name and a large size. This will
  overwrite the size of the first cache.
* Allocate one large and one small cache, then free the large one. This will
  generate an unsorted chunk.
* Read as much as possible from the victim cache. This will reveal unsorted bin
  links (which point to libc), cache vtable (which points to the binary) and
  heap addresses.
* Write into the victim cache in order to make the small cache point to
  `free_hook`.
* Write into the small cache in order to assign `printf` to `free_hook`.
* Create a cache, write a format string that leaks a stack pointer into it,
  then erase it.
* Write into the victim cache in order to make the small cache point to
  the return address from `main()`.
* Write the ROP chain into the small cache.
  * `mmap(MAP_FIXED)` a `rwx` area.
  * `read()` shellcode into it.
  * Jump to it.
