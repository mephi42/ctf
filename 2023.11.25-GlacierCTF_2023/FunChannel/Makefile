SHELL=bash
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror -Wno-array-bounds $(EXTRA_CFLAGS)
LDFLAGS=-nostartfiles -Wl,--build-id=none -Wl,-script=shellcode.lds
SOURCES=stage1.c stage2.c
ALL=stage1.s stage1.o stage1.elf stage1.bin stage2.s stage2.o stage2.elf stage2.bin

.PHONY: all
all: $(ALL)

%.s: %.c
	$(CC) $(CFLAGS) -S $< -o $@

%.o: %.s
	$(CC) -c $< -o $@

%.elf: %.o shellcode.lds
	$(CC) $(LDFLAGS) $< -o $@

%.bin: %.elf
	objcopy -O binary --only-section=.shellcode $< $@

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM $(SOURCES)

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
