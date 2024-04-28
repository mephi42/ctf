#include <nolibc.h>

int main(void)
{
#if 0
    char *argv[] = {"/bin/ls", "-l", NULL};
    char *env[] = {NULL};
#endif
    char *argv[] = {"/bin/cat", "flag", NULL};
    char *env[] = {NULL};
    execve(argv[0], argv, env);
    /* midnight{awWWw_y0u_f0uND_my_Fl4G} */
}
