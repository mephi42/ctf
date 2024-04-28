all: pwnit

pwnit: pwnit.c
	$(CC) -Wall -Wextra -Werror -Os -nostdlib -static $(CFLAGS) $< -o $@
