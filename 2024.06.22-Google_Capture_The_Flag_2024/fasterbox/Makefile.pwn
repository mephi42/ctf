pwnit: pwnit.c
	musl-gcc -o $@ -static -pthread -Os -Wall -Wextra -Werror -isystem. $<

.PHONY: fmt
fmt:
	clang-format -i pwnit.c
