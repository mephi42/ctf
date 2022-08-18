#include <stdio.h>
#include <stdlib.h>
static const char b62[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
int main(int argc, char **argv) {
  srand(atoi(argv[1]));
  for (int i = 0; i < 48; i++)
    printf("%c", b62[rand() % 62]);
  printf("\n");
}