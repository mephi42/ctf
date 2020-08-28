riscv64.hex: riscv64 tohex2 verify2
		./tohex2 <$< >$@.tmp
		./verify2 <$@.tmp
		mv $@.tmp $@

riscv64: riscv64.elf
		riscv64-linux-gnu-objcopy -O binary $< $@

riscv64.elf: riscv64.o
		riscv64-linux-gnu-ld -o $@ $<

riscv64.o: riscv64.S
		riscv64-linux-gnu-gcc -c -o $@ $<



aarch64.hex: aarch64 tohex
		./tohex <$< >$@.tmp
		mv $@.tmp $@

aarch64: aarch64.elf
		aarch64-linux-gnu-objcopy -O binary $< $@

aarch64.elf: aarch64.o
		aarch64-linux-gnu-ld -o $@ $<

aarch64.o: aarch64.S
		aarch64-linux-gnu-gcc -c -o $@ $<
