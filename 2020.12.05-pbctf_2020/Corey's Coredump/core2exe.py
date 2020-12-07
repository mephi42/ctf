#!/usr/bin/env python3
import struct
import subprocess

from elftools.elf.elffile import ELFFile


def iter_segments(core):
    for seg in core.iter_segments():
        if seg['p_type'] != 'PT_LOAD':
            continue
        if seg['p_vaddr'] >= 0x700000000000:
            continue
        if seg['p_filesz'] == 0:
            continue
        yield seg


def main():
    xor = (
        (0x5555555552c2, 0x520a0783),
        (0x5555555552c6, 0x736f6345),
        (0x555555555d65, 0x3eaf7552),
        (0x555555555d69, 0x096ada82),
        (0x555555555492, 0x6d5f6540),
        (0x555555555496, 0x52b7ed5e),
    )
    with open('core', 'rb') as core_fp, \
            open('exe.s', 'w') as asm_fp:
        core = ELFFile(core_fp)
        asm_fp.write('''.globl __init_array_start
__init_array_start:
.globl __init_array_end
__init_array_end:
''')
        args = [
            'gcc',
            '-o', 'exe',
            '-no-pie',
            '-Wl,--build-id=none',
            '-Wl,--no-relax',
            '-Wl,--defsym=main=0x555555555220',
            '-Wl,--no-as-needed',
            '-lcrypto',
        ]
        min_vaddr = None
        for i, seg in enumerate(iter_segments(core)):
            vaddr = seg['p_vaddr']
            if min_vaddr is None or vaddr < min_vaddr:
                min_vaddr = vaddr
            seg_flags = seg['p_flags']
            sec_flags = 'a'
            if seg_flags & 1:  # PF_W
                sec_flags += 'x'
            if seg_flags & 2:  # PF_X
                sec_flags += 'w'
            asm_fp.write(f'''.section .seg{i}, "{sec_flags}"
.byte''')
            first = True
            seg_data = bytearray(seg.data())
            for xor_addr, xor_mask in xor:
                if vaddr <= xor_addr < vaddr + seg['p_filesz']:
                    xor_off = xor_addr - vaddr
                    xor_val, = struct.unpack(
                        '<I', seg_data[xor_off:xor_off + 4])
                    xor_val ^= xor_mask
                    seg_data[xor_off:xor_off + 4] = struct.pack('<I', xor_val)
            for b in seg_data:
                if first:
                    first = False
                else:
                    asm_fp.write(',')
                asm_fp.write(f' 0x{b:02x}')
            asm_fp.write('\n')
            args.append(f'-Wl,--section-start=.seg{i}=0x{vaddr:x}')
    args.append('exe.s')
    subprocess.check_call(args)


if __name__ == '__main__':
    main()
