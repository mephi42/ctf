# SecureEnv

## Description

```
nc 49.234.137.149 12421
```

[SecureEnv](secureenv_26412afc95c23da51eb8726910bf9547.tar.xz)

## Summary

This is a pwn challenge. We are given a binary and a shared library; the binary
does not work out of the box:

```
./secure: error while loading shared libraries: libsgx_urts.so: cannot open shared object file: No such file or directory
```

The server asks for a blob and closes the connection:

```
 _____ ____ _____ _____   ____   ___ ____   ___  
|_   _/ ___|_   _|  ___| |___ \ / _ \___ \ / _ \ 
  | || |     | | | |_      __) | | | |__) | | | |
  | || |___  | | |  _|    / __/| |_| / __/| |_| |
  |_| \____| |_| |_|     |_____|\___/_____|\___/ 
 ____                           
/ ___|  ___  ___ _   _ _ __ ___ 
\___ \ / _ \/ __| | | | '__/ _ \
 ___) |  __/ (__| |_| | | |  __/
|____/ \___|\___|\__,_|_|  \___|
 _____            _                                      _   
| ____|_ ____   _(_)_ __ ___  _ __  _ __ ___   ___ _ __ | |_ 
|  _| | '_ \ \ / / | '__/ _ \| '_ \| '_ ` _ \ / _ \ '_ \| __|
| |___| | | \ V /| | | | (_) | | | | | | | | |  __/ | | | |_ 
|_____|_| |_|\_/ |_|_|  \___/|_| |_|_| |_| |_|\___|_| |_|\__|

Please input size: 1
Please input secret: A
```

Not much else to see here, let's dive right in.

## TL;DR

* [Exploit](shellcode.c)
* [Intel SGX](https://en.wikipedia.org/wiki/Software_Guard_Extensions)
* Install the [driver](
  https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/LD_1.33.1/driver/linux
  ) and [SDK](https://download.01.org/intel-sgx/sgx-linux/2.11/distro/) in
  order to run the binary.
* Build [gdb-sgx](
  https://github.com/intel/linux-sgx/tree/sgx_2.11/sdk/debugger_interface/linux)
  in order to debug the enclave.
* [Step through](gdbscript) library layers in order to reach the challenge
  logic.
* The blob is a shellcode that runs inside the enclave.
* The SGX memory protection is asymmetric, so overwrite `main()` return address
  with [one-gadget](https://github.com/david942j/one_gadget).
* The shell appears:
```
$ ./getflag
flag{Th3_SGX_memory_protection_1s_asymmetric}
```

## SGX

The missing `libsgx_urts.so` is not part of any Ubuntu or Fedora package,
it can be found only in [intel/linux-sgx](https://github.com/intel/linux-sgx)
repo. So what is [Intel SGX](
https://en.wikipedia.org/wiki/Software_Guard_Extensions)? It's a processor
feature, that allows running code in an isolated enclave, so that the system
(this includes kernel and hypervisors) has very limited capabilities of
observing and interfering with its execution.

The workflow is as follows. First, the launcher process creates the enclave and
loads the code into it using [`sgx_create_enclave()`](
https://github.com/intel/linux-sgx/blob/sgx_2.11/common/inc/sgx_urts.h#L88).
The enclave defines so-called ecalls, which allow triggering code execution
within it using [`sgx_ecall()`](
https://github.com/intel/linux-sgx/blob/sgx_2.11/common/inc/sgx_edger8r.h#L79).
It's convenient to think of ecalls as syscalls, because they also define a
security boundary. Finally, [`sgx_destroy_enclave()`](
https://github.com/intel/linux-sgx/blob/sgx_2.11/common/inc/sgx_urts.h#L129)
can be used to destroy the enclave.

The enclave is [mapped](
https://sgx101.gitbook.io/sgx101/sgx-bootstrap/enclave#memory-layout-of-enclave-virtual-memory)
into its launcher's address space. SGX's tamper protection works in a single
direction: the launcher cannot mess with the enclave, but the enclave can mess
with the launcher. In particular, it can dereference pointers passed to its
ecalls.

In order to run the program, I installed all the prebuilt Fedora RPMs from the
[SDK](https://download.01.org/intel-sgx/sgx-linux/2.11/distro/). There is also
a [driver](
https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/LD_1.33.1/driver/linux
) which one has to build and `insmod`. Unfortunately SDK does not include the [
gdb wrapper](
https://github.com/intel/linux-sgx/tree/sgx_2.11/sdk/debugger_interface/linux),
which I also had to build manually:
```
linux-sgx$ cd sdk/debugger_interface/linux
linux$ make
linux$ cd ../../../build/linux/gdb-sgx-plugin
gdb-sgx-plugin$ sed -i -e "s!@SDK_LIB_PATH@!$PWD/..!g" sgx-gdb
gdb-sgx-plugin$ sudo ./sgx-gdb
```

## Reversing

The binary `secure` is a simple launcher: it creates the enclave, passes the
user's blob to its ecall, and destroys the enclave.
```
  alarm(180);
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  if (sgx_create_enclave(
    /* file_name            */ "env.signed.so",
    /* debug                */ 1,
    /* launch_token         */ NULL,
    /* launch_token_updated */ NULL,
    /* enclave_id           */ &g_enclave,
    /* misc_attr            */ NULL)) {
    puts("SGX initialization failed!");
    return -1;
  }
  memset(secret, 0xc3, sizeof(secret));
  memset(size_buf, 0, sizeof(size_buf));
  print_logo();
  printf("Please input size: ");
  readln(size_buf, sizeof(size_buf));
  size = strtol(size_buf, 0, 10);
  if (size > 0x1000) {
    puts("Size too large!");
    return 1;
  }
  printf("Please input secret: ");
  readn(secret, size);
  secret_ptr = secret;
  sgx_ecall(
    /* eid         */ g_enclave,
    /* index       */ 0,
    /* ocall_table */ &g_ocall_table,
    /* ms          */ &secret_ptr)
  sgx_destroy_enclave(g_enclave);
  return 0;
```

So the shared library - `env.signed.so` - must be the enclave. It links
statically with SGX runtime, for which we have the sources, so [pigaios](
https://github.com/joxeankoret/pigaios) should be great to recover function
names. Unfortunately, it did not work for me this time - it built the database,
but then could not find any matches. Therefore I had to spend some time
correlating asm with sources in order to find the ecall logic.

The call chain is as follows:

* [`enclave_entry()`](
  https://github.com/intel/linux-sgx/blob/sgx_2.11/sdk/trts/linux/trts_pic.S#L93
  ) - this is a public symbol.
* [`enter_enclave()`](
  https://github.com/intel/linux-sgx/blob/sgx_2.11/sdk/trts/trts_nsp.cpp#L76
  ) @ `0x6720`
* [`do_ecall()`](
  https://github.com/intel/linux-sgx/blob/sgx_2.11/sdk/trts/trts_ecall.cpp#L372
  ) @ `0x1ca0`
* [`trts_ecall()`](
  https://github.com/intel/linux-sgx/blob/sgx_2.11/sdk/trts/trts_ecall.cpp#L248
  ) @ `0x18c0`. This one references `g_ecall_table` @ `0x208dd0`, which has the
  addresses of ecall handlers (just one in this case).
* `challenge_ecall()` @ `0x5a0`
* jump to shellcode @ `0x594`

Note that `&secret_ptr` is passed unchanged through all the layers - there is
no complicated marshalling. `challenge_ecall` does the following:
```
  if (!mr)
    return SGX_ERROR_INVALID_PARAMETER;
  if (!sgx_is_outside_enclave(mr, sizeof(void *)))
    return SGX_ERROR_INVALID_PARAMETER;
  sgx_lfence();
  secret_ptr = *mr;
  if (!secret_ptr) {
    sgx_lfence();
    memcpy(secret, NULL, sizeof(secret));
    ((void *(*)(void))secret)();
    return 0;
  }
  if (!sgx_is_outside_enclave(secret_ptr, 0x1000))
    return SGX_ERROR_INVALID_PARAMETER;
  sgx_lfence();
  p = malloc(0x1000);
  if (!p)
    return SGX_ERROR_OUT_OF_MEMORY;
  if (!memcpy_s(p, 0x1000, secret_ptr, 0x1000)) {
    memcpy(secret, p, sizeof(secret));
    ((void *(*)(void))secret)();
    free(p);
    return 0;
  }
  free(p);
  return 1;
```

So we just jump to the shellcode. In the debugger we can see that on entry to
shellcode `&secret_ptr` is stored in `%r13`.

## Exploitation

With all that knowledge writing [shellcode](shellcode.c) is easy: figure out
the distance between `&secret_ptr` and `main()` return address, read the
latter, compute the libc base, compute one-gadget address, overwrite `main()`
return address with it, store a bunch of zeroes below it in order to satisfy
one-gadget constraints, done.

## Conclusion

This is a nice SGX intro challenge - even though the exploitation part is
trivial, the main difficulties are to understand the technology, configure the
development setup and reverse engineer the enclave.
