# Flag controller (mini writeup)

* A flash image is given.
* Extraction step 1: convert to a flat file with [uf2conv.py](
  https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2conv.py).
* Extraction step 2: find a [littlefs](
  https://github.com/littlefs-project/littlefs) image at offset `000a0000` and
  extract it.
* Extraction step 3: struggle with littlefs tooling, which is all thoroughly
  broken, and just rip the files out with Python. The data is contiguous and
  littlefs tooling at least gives the correct file names and sizes, so it's
  enough to guess the beginnings.
* Inside there is a [micropython](https://micropython.org/) bytecode file,
  which checks the flag.
* Build micropython with the following patch:

```diff
diff --git a/ports/unix/mpconfigport.h b/ports/unix/mpconfigport.h
index d838f42b3..21a9decab 100644
--- a/ports/unix/mpconfigport.h
+++ b/ports/unix/mpconfigport.h
@@ -80,7 +80,7 @@
 #define MICROPY_STREAMS_POSIX_API   (1)
 #define MICROPY_OPT_COMPUTED_GOTO   (1)
 #ifndef MICROPY_OPT_CACHE_MAP_LOOKUP_IN_BYTECODE
-#define MICROPY_OPT_CACHE_MAP_LOOKUP_IN_BYTECODE (1)
+#define MICROPY_OPT_CACHE_MAP_LOOKUP_IN_BYTECODE (0)
 #endif
 #define MICROPY_MODULE_WEAK_LINKS   (1)
 #define MICROPY_CAN_OVERRIDE_BUILTINS (1)
```

  using the following commands:

```
mpy-cross$ make CFLAGS_EXTRA=-m32 LDFLAGS_EXTRA=-m32
ports/unix$ make CFLAGS_EXTRA=-m32 LDFLAGS_EXTRA=-m32 DEBUG=1 FROZEN_MANIFEST=
```

  This makes it compatible with the bytecode.

* Use `micropython -v -v` to print the bytecode in text format.
* Decompile by hand. Despite list comprehension abuse, the code is simple and
  there is not too much of it to boot. The code computes CRC-32 from the flag
  using different polynomials and compares the results against fixed values.
* Guess the length and solve the system of linear equations to get the flag.
