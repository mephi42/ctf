OBJCOPY=objcopy
OBJDUMP=objdump
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror

.PHONY: all
all: shellcode.s shellcode.elf shellcode.bin shellcode.objdump shellcode.stdin

shellcode.s: shellcode.c
	$(CC) $(CFLAGS) -S $<

shellcode.elf: shellcode.s shellcode.lds
	$(CC) $(CFLAGS) -nostartfiles -Wl,-script=shellcode.lds $< -o $@

shellcode.bin: shellcode.elf
	objcopy -O binary --only-section=.shellcode $< $@

shellcode.objdump: shellcode.bin
	objdump -b binary -m i386:x86-64 -D $< >$@

shellcode.stdin: shellcode.bin
	(stat --printf="%s\n" $< && cat $< && echo "ls -la && ./getflag") >$@

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM shellcode.c

.PHONY: clean
clean:
	rm -f shellcode.s shellcode.elf shellcode.bin shellcode.objdump shellcode.stdin
