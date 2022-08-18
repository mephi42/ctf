#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  int fd = open("index", O_CREAT | O_RDWR, 0600);
  assert(fd != -1);
  int ret = ftruncate(fd, 0x400000000L);
  assert(ret == 0);
  void *p = mmap(NULL, 0x400000000L, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  assert(p != MAP_FAILED);
  for (unsigned long i = 0; i < 0x100000000L; i++) {
    srand(i);
    unsigned int hash = 0;
    for (int j = 0; j < 16; j++) {
      hash = (hash << 2) ^ (rand() % 62);
    }
    ((unsigned int *)p)[hash] = i;
  }
  ret = close(fd);
  assert(ret == 0);
}