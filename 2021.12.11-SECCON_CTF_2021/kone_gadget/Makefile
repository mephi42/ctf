WORKDIR=/tmp

.PHONY: clibpoard
clipboard: pwnit.sh
	xclip -selection c <pwnit.sh

pwnit.sh: pwnit.gz.b64
	(echo 'rm -f $(WORKDIR)/pwnit && base64 -d <<HERE | gzip -d >$(WORKDIR)/pwnit && chmod a+x $(WORKDIR)/pwnit && $(WORKDIR)/pwnit' && cat pwnit.gz.b64 && echo 'HERE') >pwnit.sh

pwnit.gz.b64: pwnit.gz
	base64 <pwnit.gz >pwnit.gz.b64

pwnit.gz: pwnit
	gzip -9 <pwnit >pwnit.gz

pwnit: v02-leak-ebx.c
	musl-gcc -o pwnit -static -pthread -Os -Wall -Wextra -Wno-array-bounds -pedantic -Werror v02-leak-ebx.c

.PHONY: fmt
fmt:
	clang-format -i pwnit.c
