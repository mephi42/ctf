/*
 * This is a demo program to show how to interact with ATOMS.
 * Don't waste time on finding bugs here ;)
 *
 * Copyright (c) 2020 david942j
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ATOMS_USE_TOKEN 0x4008D900
#define ATOMS_ALLOC 0xC010D902
#define ATOMS_RELEASE 0xD903
#define ATOMS_MEM_INFO 0x8018D901
#define ATOMS_BOGUS 0x66666666

struct atoms_ioctl_alloc {
  size_t size;
  size_t total_pages;
};

struct atoms_ioctl_info {
  unsigned long token;
  size_t n_pages;
  size_t n_atoms;
};

#define DEV_PATH "/dev/atoms"
#define TOKEN 0xdeadbeef

int main(void) {
  int fd = open(DEV_PATH, O_RDWR);
  assert(fd >= 0);
  assert(ioctl(fd, ATOMS_USE_TOKEN, TOKEN) == 0);
  assert(ioctl(fd, ATOMS_BOGUS) != 0);
  pid_t pid = fork();
  assert(pid != -1);
  if (pid == 0)
    assert(ioctl(fd, ATOMS_BOGUS) != 0);
}
