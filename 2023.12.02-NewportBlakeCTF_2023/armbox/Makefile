SHELL=bash
CC=arm-linux-gnueabihf-gcc
CFLAGS=-Os -fno-stack-protector -fcf-protection=none -Wall -Wextra -Werror $(EXTRA_CFLAGS) -marm
# Ignore "PHDR segment not covered by LOAD segment"
LDFLAGS=-nostartfiles -Wl,--build-id=none -Wl,-script=shellcode.lds -Wl,--noinhibit-exec
SOURCES=pwnit.c
ALL=pwnit.s pwnit.o pwnit.elf pwnit.bin

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
	truncate -s 65536 $@

.PHONY: pwn
pwn: pwnit.bin
	nc chal.nbctf.com 30176 <$<

.PHONY: fmt
fmt:
	clang-format -i -style=LLVM $(SOURCES)

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
