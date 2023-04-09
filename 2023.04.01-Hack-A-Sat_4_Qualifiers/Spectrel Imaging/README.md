# Spectrel Imaging (mini writeup)

* Timing attack challenge. The binary works roughly as follows:
  ```
  char stars[200][256];
  char sequence[256];
  char flag[128];

  ...

  t0 = rdtsc();
  if (i >= 256) throw;
  j = sequence[i];
  write(fd, stars[j], strlen(stars[j]));
  printf("%d\n", rdtsc() - t0);
  ```
  `i` is controlled by the user. The code above can be run any number of times.
* Flush caches (there is a special request for that).
* Train branch prediction to assume we don't throw.
  128 "clean" runs seem to be enough.
* Perform single out-of-bounds request.
  * `strlen()` will speculatively access one of the stars, depending on what's
    in `flag[i - 256]`. It will be loaded into cache, and the others won't.
* Make 256 clean runs, accessing stars 0 - 255. Working with one of them will
  be slightly faster, due to it being in cache and having to fetch others from
  RAM.
* Repeat the above measurements 512 times (this may be an overkill).
* Take median values (minimum and average don't appear to work well) of
  measurements corresponding to each value of `i`. The smallest one is the
  value of `flag[i - 256]`.
