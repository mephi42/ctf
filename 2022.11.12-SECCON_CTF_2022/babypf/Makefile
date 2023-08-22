WORKDIR=/tmp

.PHONY: clibpoard
clipboard: pwnit.sh
	xclip -selection c <$<

pwnit.sh: pwnit.gz.b64
	(echo 'rm -f $(WORKDIR)/pwnit && base64 -d <<HERE | gzip -d >$(WORKDIR)/pwnit && chmod a+x $(WORKDIR)/pwnit && $(WORKDIR)/pwnit' && cat $< && echo 'HERE') >$@

pwnit.gz.b64: pwnit.gz
	base64 <$< >$@

pwnit.gz: pwnit
	gzip -9 <$< >$@

pwnit: pwnit.c
	musl-gcc -o $@ -static -pthread -Os -Wall -Wextra -pedantic -Werror $<

.PHONY: fmt
fmt:
	clang-format -i pwnit.c

.PHONY: clean
clean:
	rm -f pwnit.sh pwnit.gz.b64 pwnit.gz pwnit
