.PHONY: clibpoard
clipboard: pwnit.sh
	xclip -selection c <pwnit.sh

pwnit.sh: pwnit.xz.b64
	(echo 'rm -f /tmp/pwnit && base64 -d <<HERE | xz -d >/tmp/pwnit && chmod a+x /tmp/pwnit && /tmp/pwnit' && cat pwnit.xz.b64 && echo 'HERE') >pwnit.sh

pwnit.xz.b64: pwnit.xz
	base64 <pwnit.xz >pwnit.xz.b64

pwnit.xz: pwnit
	xz -9 <pwnit >pwnit.xz

pwnit: v01-pwnit.c
	musl-gcc -o pwnit -static -pthread -Os -Wall -Wextra -pedantic -Werror -isystem. v01-pwnit.c

.PHONY: fmt
fmt:
	clang-format -i v01-pwnit.c
