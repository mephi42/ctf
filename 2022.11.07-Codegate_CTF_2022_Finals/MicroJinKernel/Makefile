SHELL=bash
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror

.PHONY: all
all: shellcode.s shellcode.elf shellcode.bin

shellcode.s: shellcode.c
	$(CC) $(CFLAGS) -S $<

shellcode.elf: shellcode.s shellcode.lds
	$(CC) $(CFLAGS) -nostartfiles -Wl,--build-id=none -Wl,-script=shellcode.lds $< -o $@

shellcode.bin: shellcode.elf
	objcopy -O binary --only-section=.shellcode $< $@

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM shellcode.c

.PHONY: clean
clean:
	rm -f shellcode.s shellcode.elf shellcode.bin

.DELETE_ON_ERROR:
