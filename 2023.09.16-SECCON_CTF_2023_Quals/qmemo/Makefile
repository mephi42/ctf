.PHONY: clibpoard
clipboard: pwnit.sh
	xclip -selection c <pwnit.sh

pwnit.sh: pwnit.gz.b64
	(echo 'rm -f /tmp/pwnit && base64 -d <<HERE | gzip -d >/tmp/pwnit && chmod a+x /tmp/pwnit && /tmp/pwnit' && cat pwnit.gz.b64 && echo 'HERE') >pwnit.sh

pwnit.gz.b64: pwnit.gz
	base64 <pwnit.gz >pwnit.gz.b64

pwnit.gz: pwnit
	gzip -9 <pwnit >pwnit.gz

pwnit: pwnit.c
	musl-gcc -o pwnit -static -pthread -Os -Wall -Wextra -Werror -isystem. pwnit.c

.PHONY: fmt
fmt:
	clang-format -i pwnit.c
