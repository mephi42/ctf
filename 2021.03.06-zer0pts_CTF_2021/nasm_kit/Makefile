SHELL=bash
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror

.PHONY: all
all: shellcode.s shellcode.elf shellcode.bin shellcode-nasm.s

shellcode.s: shellcode.c
	$(CC) $(CFLAGS) -S $<

shellcode.elf: shellcode.s shellcode.lds
	$(CC) $(CFLAGS) -nostartfiles -Wl,--build-id=none -Wl,-script=shellcode.lds $< -o $@

shellcode.bin: shellcode.elf
	objcopy -O binary --only-section=.shellcode $< $@

shellcode-nasm.s: shellcode.bin ndisasm.py
	./ndisasm.py shellcode.bin >shellcode-nasm.s
	# diff shellcode.bin <(nasm -fbin -o /dev/stdout shellcode-nasm.s)

.PHONY: fmt
fmt:
	black ndisasm.py
	clang-format -i -style=LLVM shellcode.c

.PHONY: clean
clean:
	rm -f shellcode.s shellcode.elf shellcode.bin shellcode-nasm.s

.DELETE_ON_ERROR:
