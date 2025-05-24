.PHONY: clibpoard
clipboard: pwnit.sh
	xclip -selection c <pwnit.sh

pwnit.sh: pwnit.xz.b64
	(echo 'rm -f /home/user/p && base64 -d <<HERE | xz -d >/home/user/p && chmod a+x /home/user/p && /home/user/p' && cat pwnit.xz.b64 && echo 'HERE') >pwnit.sh

pwnit.xz.b64: pwnit.xz
	base64 <pwnit.xz >pwnit.xz.b64

pwnit.xz: pwnit
	xz -9 <pwnit >pwnit.xz

pwnit: pwnit.c
	musl-gcc -o pwnit -static -pthread -Os -Wall -Wextra -Werror -isystem. pwnit.c

.PHONY: fmt
fmt:
	clang-format -i pwnit.c
