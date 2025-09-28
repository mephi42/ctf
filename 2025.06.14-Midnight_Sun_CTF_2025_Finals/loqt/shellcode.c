#include <nolibc.h>

__attribute__((section(".entry"))) int main(void)
{
    mkdir("chroot-dirs", 0755);
    chroot("chroot-dir");
    for (int i = 0; i < 16; i++) chdir("..");
    chroot(".");

    char *argv[] = {"/bin/sh", NULL};
    char *env[] = {NULL};
    execve(argv[0], argv, env);
}
