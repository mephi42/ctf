#include <assert.h>
#include <stdio.h>
#include <string.h>

struct table {
  long data[624];
  int count;
};

void gen_table(struct table *a1, long a2) {
  long *v2;

  v2 = &a1->data[1];
  a1->data[0] = (unsigned int)a2;
  while (1) {
    a2 = (unsigned int)(6069 * a2);
    *v2 = a2;
    if (v2 == &a1->data[623])
      break;
    ++v2;
  }
  a1->count = 624;
}

long qword_5555555570C0[] = {0, 0x9908B0DF};

unsigned int step_table(struct table *a1) {
  long v1;
  int v2;
  long i;
  unsigned long v4;
  unsigned long v5;
  unsigned long v6;
  long *v8;
  long v9;
  long data[624];

  v1 = a1->count;
  v2 = v1 + 1;
  if (v1 > 623) {
    if (v1 != 624) {
      a1->data[0] = 4357;
      v8 = &a1->data[1];
      v9 = 4357;
      while (1) {
        v9 = (unsigned int)(6069 * v9);
        *v8 = v9;
        if (v8 == &a1->data[623])
          break;
        ++v8;
      }
    }
    memcpy(data, a1, sizeof(data));
    for (i = 1; i != 625; ++i) {
      v4 = data[i - 1] & 0x80000000LL | data[i % 0x270] & 0x7FFFFFFF;
      a1->data[i - 1] =
          qword_5555555570C0[v4 & 1] ^ a1->data[(i + 396) % 624] ^ (v4 >> 1);
    }
    v2 = 1;
    v1 = 0LL;
  }
  v5 = a1->data[v1];
  a1->count = v2;
  v6 = (((unsigned int)v5 ^ (unsigned int)(v5 >> 11)) << 7) & 0x9D2C5680 ^ v5 ^
       (v5 >> 11) ^
       (((((unsigned int)v5 ^ (unsigned int)(v5 >> 11)) << 7) & 0x9D2C5680 ^
         (unsigned int)v5 ^ (unsigned int)(v5 >> 11))
        << 15) &
           0xEFC60000;
  return (v6 >> 18) ^ v6;
}

char tmp_secure[] = {0xcc, 0xd2, 0x9e, 0x92, 0xde, 0xd6,
                     0x81, 0xe6, 0x92, 0x8b, 0x97};
char xxx[] = {0xed, 0xb0, 0xc4, 0xdb, 0xc9, 0xe6, 0xef, 0xde};
char yyy[] = {0xd6, 0x8c, 0xeb, 0x97, 0xcb, 0x83, 0x87, 0xea, 0x8d,
              0xb9, 0x86, 0x90, 0xe7, 0xfa, 0xcf, 0xcd, 0xb1};
char zzz[] = {0xbe, 0xb9, 0xbb, 0xaa, 0xab, 0xd9, 0x80, 0x93, 0xc2, 0xae, 0x98,
              0xdf, 0xbc, 0x88, 0xc0, 0xf9, 0xf7, 0xa2, 0x9b, 0xde, 0xb0, 0xe7,
              0xf4, 0xce, 0xac, 0x86, 0xe3, 0xc5, 0x94, 0x8f, 0xac, 0xe2};
char qqq[] = {0xee, 0x8a, 0xdf, 0xe9, 0xc4, 0xf3,
              0x94, 0xb8, 0xdf, 0xba, 0x84, 0xe3};
char ttt[] = {0xfc, 0xce, 0xee, 0xcd, 0x84, 0xbf, 0xc0, 0xe7, 0xc3,
              0x99, 0xbe, 0xde, 0x8d, 0xdf, 0xeb, 0xa4, 0xb0};
char mmm[] = {0x7c, 0xa1, 0xdc, 0x09, 0x86, 0x93, 0x9b, 0xa5, 0x96, 0xbc,
              0x75, 0xd6, 0x38, 0x54, 0x51, 0xa9, 0xe3, 0x54, 0xb7, 0x5c,
              0x6c, 0x46, 0xc8, 0x09, 0xfd, 0xab, 0x2f, 0x11, 0x1a, 0x8d,
              0x70, 0xb6, 0x44, 0xee, 0xd8, 0x68, 0xa5, 0x34, 0x86, 0xf6,
              0x4f, 0x1c, 0xb4, 0x03, 0x3e, 0x66, 0x6d, 0xce, 0x28, 0xa2,
              0x47, 0x95, 0xe4, 0x30, 0x4a, 0xa9, 0xeb, 0xb6, 0x88, 0xe4,
              0x47, 0x7a, 0xd5, 0x9a, 0xd8, 0xa9, 0x52, 0x3e, 0x9f, 0xae,
              0x80, 0x6c, 0xab, 0x6c, 0x4f, 0xb7, 0x9a, 0xc7, 0x76, 0x69,
              0x55, 0x45, 0x68, 0x4b, 0x10, 0x49, 0x41, 0x90, 0x6e, 0x13,
              0x89, 0xf4, 0x67, 0xbe, 0x8a, 0xd5, 0x07, 0x82, 0x15, 0x4b};
char mask[] = {'m', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '_', 'i', 's',
               '_', 's', 'e', 'c', 'u', 'r', 'e', '!', '!', 0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
               0,   0,   0,   0,   0,   0,   0,   0,   0};

int main() {
  struct table t;

  gen_table(&t, (0x5555555552c2 - 3) & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, (0x55555555705e & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(tmp_secure) / sizeof(tmp_secure[0]); i++)
    printf("%c", tmp_secure[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  gen_table(&t, (0x555555557070 & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(xxx) / sizeof(xxx[0]); i++)
    printf("%c", xxx[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  gen_table(&t, (0x55555555707c & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(yyy) / sizeof(yyy[0]); i++)
    printf("%c", yyy[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  gen_table(&t, (0x555555557093 & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(zzz) / sizeof(zzz[0]); i++)
    printf("%c", zzz[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  gen_table(&t, 0x5555555554CD & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, 0x555555555508 & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, 0x555555555539 & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, 0x555555555DC2 & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, 0x555555555467 & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, 0x555555555CCA & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));

  gen_table(&t, (0x555555557037 & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(qqq) / sizeof(qqq[0]); i++)
    printf("%c", qqq[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  gen_table(&t, (0x555555557049 & 0xfff));
  printf("<");
  for (int i = 0; i < sizeof(ttt) / sizeof(ttt[0]); i++)
    printf("%c", ttt[i] ^ ((step_table(&t) | 0x80) & 0xff));
  printf(">\n");

  assert(sizeof(mmm) == sizeof(mask));

  struct table t2;
  gen_table(&t2, 0x0b1584c802e81d67LL);
  unsigned int r10d = step_table(&t2) & 0xfff;
  for (int j = 0; j < r10d; j++)
    for (int i = 0; i < sizeof(mmm) / sizeof(mmm[0]); i++)
      mmm[i] ^= step_table(&t2) & 0xff;

  for (int i = 0; i < sizeof(mmm) / sizeof(mmm[0]); i++)
    mmm[i] ^= mask[i];

  gen_table(&t, (0x7fffffffc843 & 0xfff));
  for (int i = 0; i < sizeof(mmm) / sizeof(mmm[0]) && mmm[i]; i++)
    mmm[i] ^= (step_table(&t) | 0x80) & 0xff;

  for (int i = 0; i < sizeof(mmm) / sizeof(mmm[0]); i++)
    printf("%02x", mmm[i] & 0xff);
  printf("\n");
  printf("<");
  for (int i = 0; i < sizeof(mmm) / sizeof(mmm[0]); i++)
    printf("%c", mmm[i] & 0xff);
  printf(">\n");
  printf("d0=0x%lx\n", t2.data[0]);
  printf("count=%d\n", t2.count);

  gen_table(&t, 0x555555555CB2 & 0xfff);
  printf("%x\n", step_table(&t));
  printf("%x\n", step_table(&t));
}
