.PHONY: all
all: pwn

.PHONY: pwn
pwn: pwnit.exe
	sshpass -p seccon scp pwnit.exe seccon@192.168.122.250:/tmp/
	sshpass -p seccon ssh seccon@192.168.122.250 /tmp/pwnit.exe

.PHONY: fmt
fmt:
	clang-format -i pwnit.c

pwnit.exe: pwnit.c
	x86_64-w64-mingw32-gcc -Wall -Wextra -Werror -Os $< -o $@ -lntdll

ntoskrnl.exe:
	# vagrant ssh -- copy \\windows\\system32\\ntoskrnl.exe \\vagrant
	sshpass -p seccon scp seccon@192.168.122.250:/windows/system32/ntoskrnl.exe .

.PHONY: ssh-admin
ssh-admin:
	sshpass -p vagrant ssh vagrant@192.168.122.250

.PHONY: driver
driver:
	sshpass -p vagrant scp -r dists vagrant@192.168.122.250:/tmp/
	sshpass -p vagrant ssh vagrant@192.168.122.250 bcdedit /set testsigning on
