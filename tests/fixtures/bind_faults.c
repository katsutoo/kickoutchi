#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef int (*bind_function)(int, const struct sockaddr *, socklen_t);

static bind_function native_bind(void) {
    return (bind_function)dlsym(RTLD_NEXT, "bind");
}

int bind(int socket_fd, const struct sockaddr *address, socklen_t length) {
    bind_function call_native = native_bind();
    const char *mode = getenv("KICKOUTCHI_TEST_BIND_FAULT_MODE");
    if (call_native == NULL || mode == NULL || address == NULL) {
        return call_native == NULL ? -1 : call_native(socket_fd, address, length);
    }

    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        uint32_t host = ntohl(ipv4->sin_addr.s_addr);
        if (host == INADDR_LOOPBACK) {
            errno = EACCES;
            return -1;
        }
        if (host == INADDR_ANY) {
            errno = EADDRINUSE;
            return -1;
        }
    }

    if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        if (IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr)) {
            errno = strcmp(mode, "mixed") == 0 ? ECONNREFUSED : EACCES;
            return -1;
        }
        if (IN6_IS_ADDR_UNSPECIFIED(&ipv6->sin6_addr)) {
            if (strcmp(mode, "permission") == 0) {
                errno = EADDRINUSE;
                return -1;
            }
            if (strcmp(mode, "mixed") == 0) {
                return 0;
            }
        }
    }

    return call_native(socket_fd, address, length);
}
