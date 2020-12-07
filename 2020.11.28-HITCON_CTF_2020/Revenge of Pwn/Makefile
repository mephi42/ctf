pwnit: pwnit.c
	gcc -o pwnit -Wall -Wextra -pedantic -Werror pwnit.c  # diagnostics
	tcc -o pwnit pwnit.c  # size

.PHONY: fmt
fmt:
	clang-format -i pwnit.c
