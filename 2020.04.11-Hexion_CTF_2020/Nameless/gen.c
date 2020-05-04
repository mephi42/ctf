#include <stdio.h>
#include <stdlib.h>

int main() {
	char encflag[128], decflag[128];
	size_t len = fread(encflag, 1, 128, fopen("nameless/out.txt", "rb"));
	for (int seed = 1586649047 - 1000000; seed < 1586649047 + 1000000; seed++) {
		srand(seed);
		for (int i = 0; i < len; i++)
			decflag[i] = encflag[i] ^ ((rand() % 0x666) + 1);
		decflag[len] = 0;
		printf("%d %s\n", seed, decflag);
	}
}
