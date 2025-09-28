SHELL=bash
CC=gcc
CFLAGS=-Os -Wall -Wextra -Werror -I/usr/include/efi $(EXTRA_CFLAGS)
LDFLAGS=-static -nostdlib --build-id=none -script=shellcode.lds
SOURCES=shellcode.c
ALL=shellcode.s shellcode.o shellcode.elf shellcode.bin

.PHONY: all
all: $(ALL)

%.s: %.c
	clang --target=x86_64-windows -mno-sse $(CFLAGS) -S $< -o $@

%.o: %.s
	clang --target=x86_64-windows $(CFLAGS) -c $< -o $@

%.elf: %.o shellcode.lds
	ld $(LDFLAGS) $< -o $@

# https://wiki.osdev.org/GNU-EFI
%.efi.o: %.c
	gcc -I/usr/include/efi -fpic -ffreestanding -fno-stack-protector -fno-stack-check -fshort-wchar -mno-red-zone -maccumulate-outgoing-args -c $< -o $@

%.efi.elf: %.efi.o
	ld -shared -Bsymbolic -T/usr/lib/elf_x86_64_efi.lds /usr/lib/crt0-efi-x86_64.o $< -o $@ /usr/lib/libgnuefi.a /usr/lib/libefi.a

%.efi: %.efi.elf
	objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym  -j .rel -j .rela -j .rel.* -j .rela.* -j .reloc --target efi-app-x86_64 --subsystem=10 $< $@

%.bin: %.elf
	objcopy -O binary --only-section=.text $< $@

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM $(SOURCES)

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
