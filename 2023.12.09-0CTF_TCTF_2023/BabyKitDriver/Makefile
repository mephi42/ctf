.PHONY: all
all: pwnit

.PHONY: pwn
pwn: pwnit
	rsync -avz pwnit OSX-KVM:
	ssh OSX-KVM ./pwnit

.PHONY: fmt
fmt:
	clang-format -style LLVM -i pwnit.c

.PHONY: load
load:
	ssh -t OSX-KVM sudo sh -c "\"kextunload BabyKitDriver.kext ; kextload BabyKitDriver.kext && kextstat -b keen.BabyKitDriver\"" | tee load.log

kernel:
	rsync -avz OSX-KVM:/System/Library/Kernels/kernel .

.PHONY: diag
diag:
	ssh OSX-KVM sh -c "\"ls -t /Library/Logs/DiagnosticReports/Kernel-*.panic|head -n1|xargs cat\""

# ./configure --target=x86_64-apple-darwin13 --prefix=$HOME/gdb-x86_64-apple-darwin
.PHONY: gdb
gdb: kernel BabyKitDriver.kext/Contents/MacOS/BabyKitDriver
	x86_64-apple-darwin13-gdb -x gdbscript

pwnit: pwnit.c image/Dockerfile
	docker build -t osxcross image
	docker run -it --rm -v $(PWD):$(PWD) -w $(PWD) -u $(shell id -u):$(shell id -g) osxcross o64-clang -o $@ -Os -Wall -Wextra -Werror -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx $< -framework IOKit
