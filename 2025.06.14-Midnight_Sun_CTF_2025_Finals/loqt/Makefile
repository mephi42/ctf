SHELL=bash
CC=gcc
CFLAGS=-Os -fno-stack-protector -fcf-protection=branch -Wall -Wextra -Werror $(EXTRA_CFLAGS)
LDFLAGS=-static -nostdlib -Wl,--build-id=none -Wl,-script=shellcode.lds

.PHONY: all
all: shellcode.bin shellcode.elf

%.s: %.c
	$(CC) $(CFLAGS) -S $< -o $@

%.o: %.s
	$(CC) $(CFLAGS) -c $< -o $@

%.elf: %.o shellcode.lds
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

%.bin: %.elf
	objcopy -O binary --only-section=.shellcode $< $@

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM shellcode.c

.PHONY: clean
clean:
	rm -f shellcode.s shellcode.o shellcode.elf shellcode.bin shellcode.s

.DELETE_ON_ERROR:
