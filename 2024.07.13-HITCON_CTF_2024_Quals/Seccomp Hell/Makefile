SHELL=bash
CC=gcc
CFLAGS=-Os -fno-stack-protector -fcf-protection=branch -Wall -Wextra -Werror $(EXTRA_CFLAGS)
LDFLAGS=-static -nostdlib -Wl,--build-id=none -Wl,-script=shellcode.lds
SOURCES=stage0.c stage1.c stage2.c
ALL=stage0.s stage0.o stage0.elf stage0.bin stage0.s stage1.o stage1.elf stage1.bin stage2.s stage2.o stage2.elf stage2.bin

.PHONY: all
all: $(ALL)

%.s: %.c
	$(CC) $(CFLAGS) -S $< -o $@

%.o: %.s
	$(CC) $(CFLAGS) -c $< -o $@

%.elf: %.o shellcode.lds
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

%.bin: %.elf
	objcopy -O binary --only-section=.shellcode $< $@

stage1.s: stage2.bin
stage1.s: CFLAGS+=-DSTAGE2_SIZE=$(shell wc -c <stage2.bin)

stage0.s: stage1.bin
stage0.s: CFLAGS+=-DSTAGE1_SIZE=$(shell wc -c <stage1.bin)

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM $(SOURCES)

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
