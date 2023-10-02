SHELL=bash
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror $(EXTRA_CFLAGS)
LDFLAGS=-nostartfiles -Wl,--build-id=none -Wl,-script=shellcode.lds
ALL=stage1.s stage1.elf stage1.bin stage2.s stage2.elf stage2.bin

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

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM stage1.c stage2.c

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
