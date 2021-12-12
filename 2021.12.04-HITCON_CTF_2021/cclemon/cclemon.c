#include <stdio.h>

static long state = 68694329;

static long randlong(void) {
  state = ((state * 1259409L) + 321625345L) % 4294967296L;
  return state;
}

#define N 200000
static long values[N];

static void swap(long x, long y) {
  long tmp = values[x];
  values[x] = values[y];
  values[y] = tmp;
}

static void reverse(long x, long y) {
  if (x > y)
    return reverse(y, x);
  while (x < y) {
    swap(x, y);
    x++;
    y--;
  }
}

static void _xor(long x, long y, long val) {
  if (x > y)
    return _xor(y, x, val);
  for (long i = x; i <= y; i++)
    values[i] ^= val;
}

int main(void) {
  for (int i = 0; i < N; i++)
    values[i] = randlong();
  for (int i = 0; i < N; i += 5) {
    long choice = randlong() % 3;
    long x = randlong() % N;
    long y = randlong() % N;
    switch (choice) {
    case 0:
      reverse(x, y);
      break;
    case 1:
      swap(x, y);
      break;
    case 2:
      _xor(x, y, randlong());
      break;
    }
  }
  long result = 0;
  for (int i = 0; i < N; i++)
    result += values[i] * (i + 1);
  printf("hitcon{%ld}\n", result);
}