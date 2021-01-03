# SimpleSystem - mini writeup

* Bug: accesses to array of sessions are not synchronized.
* Create the victim session.
* Create a session, log in, initiate a long sleep (which will create a new
  thread, `malloc()` and `sleep()`), log out. Repeat 8 times - this will
  allocate the maximum amount of thread arenas, which in 64-bit applications is
  `nproc * 8`. The challenge runs with just 1 core, but for local testing a
  larger number might be required.
* Log into the victim session, initiate a short sleep, log out with deletion,
  log back in, wait. The active session and all of its buffers will be freed.
* Fullname buffer will go into the unsorted bin. "Show information" in order to
  read its `fd` pointer and obtain the libc address.
* Session object itself will go into the unsorted bin as well. This will cause
  its second qword - which is `is_admin` field, to be overwritten with a
  nonzero `bk` pointer, making it an admin session and unlocking the ability to
  add and edit notes.
* Add notes of size `0x90` in a loop.
  * Each addition will be processed in a new thread. Arenas are assigned to new
    threads in a round-robin fashion, so sooner or later the allocation will go
    into `main_arena` and overlap the active session.
  * The added notes should contain a fake session, whose fullname points a heap
    pointer within libc and which has 0 notes.
  * As soon as the overwrite happens, we will see the weird fullname in "show
    information". This will in fact be a heap address, and we should stop
    adding further notes at this point.
  * The overwrite happens before adding a note. This means that the new note,
    which covers the session object, will be still available.
* Edit the note in order to alter the victim session again.
  * Forge the fake note inside the victim session. mutex field has a lot of
    unused space - to make it the only thing that occupies the cache line I
    assume. This note should cover `free_hook`.
  * There is even more free space, so put `"/bin/sh\0"` string there and make
    fullname point to it.
* Edit the note in order to assign `system` to `free_hook`.
* Log out with deletion; the first thing this would do is `free(fullname)`,
  which will cause `system("/bin/sh")`.
* The shell and the main executable will disrupt each other's reads from stdin
  until the main executable exits, e.g. due to `SIGALRM`.
