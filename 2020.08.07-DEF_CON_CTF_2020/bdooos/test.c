#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

int main() {
	volatile long x = 0x4F06FF57E917BF93LL;
	volatile long y = 0x4F06FF57E917BF94LL;
	printf("before socket(): %lx %lx\n", x, y);
	fflush(stdin);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	printf("after socket():  %lx %lx %d\n", x, y, s);
	fflush(stdin);

	long *bd = (long *)x;
	printf("before sendto(): %016lx %016lx %016lx %016lx\n", bd[0], bd[1], bd[2], bd[3]);
	fflush(stdin);
	char message[16] = { 0xff, 0x39, 0x98, 0x8e, 0x41, 0x64, 0x19, 0x8e, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	struct sockaddr_in dontcare;
	s = sendto(s, message, sizeof(message), 0, (struct sockaddr *)&dontcare, sizeof(dontcare));
	printf("after  sendto(): %016lx %016lx %016lx %016lx %d\n", bd[0], bd[1], bd[2], bd[3], s);
	fflush(stdin);
}
