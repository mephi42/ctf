#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
 
typedef int (*orig_bind_f_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
 
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    orig_bind_f_type orig_bind;
    int enable = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    orig_bind = (orig_bind_f_type)dlsym(RTLD_NEXT, "bind");
    return orig_bind(sockfd, addr, addrlen);
}
