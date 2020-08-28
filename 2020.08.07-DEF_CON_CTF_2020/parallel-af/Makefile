libsnoop.so: snoop.c
	$(CC) -o libsnoop.so -shared -fPIC snoop.c -Wall -Werror -ldl

fmt:
	clang-format -style=LLVM -i snoop.c
