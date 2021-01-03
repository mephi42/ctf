# cache_v2 (mini writeup)

* Bug: reference count can wrap around, leading to a UAF.
* Create the large victim cache and duplicate it 256 times. This will set its
  reference count to 1.
* Create a smaller cache, then free the victim cache through an alias. Victim
  cache's buffer will go into the unsorted bin.
* Read 8 bytes the victim cache. This will give us an unsorted `fd` pointer.
  Since this is not the only unsorted chunk, `fd` is a heap pointer, not a libc
  pointer.
* Use the leaked heap pointer in order to calculate the victim cache address.
* Allocate the attacker cache that is `0x18` bytes large. Its buffer will
  overlap with the victim cache.
* Write into the attacker cache in order to make the victim cache cover the
  entire address space.
* Read the unsorted `bk` pointer of the original victim buffer. This will
  reveal the libc address.
* The rest is the same as in [cache_v1](../cache_v1).
