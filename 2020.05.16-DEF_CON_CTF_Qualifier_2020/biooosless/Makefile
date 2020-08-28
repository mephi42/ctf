CFLAGS := -m32 -march=i386 -Os -fPIC -ffunction-sections -fno-stack-protector -Wall -Wextra -Werror $(CFLAGS)

shellcode.s: shellcode
		objdump -D -b binary -mi386 $< >$@

shellcode: shellcode.elf
		objcopy -O binary -j.text $< $@

shellcode.elf: shellcode.o shellcode.lds
		ld -o $@ -m elf_i386 -nostdlib -T shellcode.lds $<

shellcode.o: shellcode.c
		gcc -c $(CFLAGS) -o $@ $<

fmt:
		clang-format -i -style=gnu shellcode.c
