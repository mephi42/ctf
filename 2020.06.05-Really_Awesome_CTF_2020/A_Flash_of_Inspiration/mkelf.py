#!/usr/bin/env python3
import subprocess

bin = open('flash.bin', 'rb').read()
with open('flash.s', 'w') as fp:
    for b in bin:
        fp.write(f'.byte 0x{b:02x}\n')
# ld/emulparams/avr35.sh:TEXT_LENGTH=64K
subprocess.check_call(['avr-gcc', '-mmcu=avr35', '-o', 'flash.elf', 'flash.s'])
