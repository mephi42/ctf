# Magic Space Bussin (mini writeup)

* x86_64 binary containing an implementation of a message bus. The user can
  send and handle messages in any order.
* Bug: entering an odd number of hex digits messes up the buffer length.
  * When sending such a message, one can overwrite the next byte with a value
    between 0 and 15. This can be used for overwriting chunk sizes.
  * When receiving such a message, one reads twice its actual length. Allows
    leaking libc (from unsorted bin link) and heap addresses.
* Goal: `free_hook = system`.
  * Achieved by injecting a `&free_hook` chunk into tcache.
    * Achieved by writing `&free_hook` into an existing tcache chunk.
      * Achieved by overlapping this tcache chunk with a fake chunk.
* Preparation: massage the heap. All real chunks contain message bodies.
  Their sizes are 0x120, so they go into tcache after being freed.
  The fake chunk is just a part of B, the heap does not know about it.
  ```
  +--------------+---------------------------+-----------------------+
  | Attacker (A) | Overflow victim (B)       | Coalescing victim (C) |
  |              |                           |                       |
  |              |             +----------- -|                       |
  |              |             |&fake1=      |                       |
  |              |             |B.end - 0x20 |                       |
  | size=0x120   | .size=0x120 |  .size=0x40 | .size=0x120           |
  +--------------+---------------------------+-----------------------+
  ```
* Bug usage: free A and allocate it again, but now fill it with an odd number
  of hex characters, overwriting B's size with 0x100.
  A is no longer relevant.
  The first fake chunk becomes real from the heap's point of view.
  ```
  +---------------------+------------+-----------------------+
  | Overflow victim (B) | fake1      | Coalescing victim (C) |
  |                     |            |                       |
  |                     | <--------> |                       |
  |                     |    0x20    |                       |
  |                     |            |                       |
  | size=0x100          | .size=0x40 | .size=0x120           |
  +---------------------+------------+-----------------------+
  ```
* Free B, which coalesces it with the first fake chunk. Now B and C overlap.
  Free C, so that it ends up in tcache.
  ```
  +---------------------+-----------------------+
  | Overflow victim (B) | Coalescing victim (C) |
  |                     |                       |
  | <-----------------> |                       |
  |        0x120        |                       |
  | in tcache           | in tcache             |
  | size=0x140          | .size=0x120           |
  +---------------------+-----------------------+
  ```
* Allocate B and overwrite C's tcache link.
  ```
  +---------------------+-----------------------+
  | Overflow victim (B) | Coalescing victim (C) |
  |                     |                       |
  | <-----------------> |                       |
  |        0x120        | in tcache             |
  |                     | .fd=&free_hook        |
  | size=0x140          | .size=0x120           |
  +---------------------+-----------------------+
  ```
* There are some additional technicalities, like having a second fake chunk
  inside C in order to satisfy heap's consistency checking. They are described
  in the exploit.
