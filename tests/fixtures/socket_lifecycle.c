#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct socket_config {
    int family;
    int type;
    int wildcard;
    int ipv6_only;
    unsigned int count;
};

static int bind_socket(const struct socket_config *config, unsigned short port,
                       unsigned short *bound_port) {
    int socket_fd = socket(config->family, config->type, 0);
    if (socket_fd < 0) {
        return -1;
    }

    int enabled = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0) {
        close(socket_fd);
        return -1;
    }
    if (config->family == AF_INET6 && config->ipv6_only >= 0 &&
        setsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &config->ipv6_only,
                   sizeof(config->ipv6_only)) < 0) {
        close(socket_fd);
        return -1;
    }

    if (config->family == AF_INET) {
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = htonl(config->wildcard ? INADDR_ANY : INADDR_LOOPBACK),
        };
        if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
            close(socket_fd);
            return -1;
        }
        socklen_t length = sizeof(address);
        if (getsockname(socket_fd, (struct sockaddr *)&address, &length) < 0) {
            close(socket_fd);
            return -1;
        }
        *bound_port = ntohs(address.sin_port);
    } else {
        struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port),
            .sin6_addr = config->wildcard ? in6addr_any : in6addr_loopback,
        };
        if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
            close(socket_fd);
            return -1;
        }
        socklen_t length = sizeof(address);
        if (getsockname(socket_fd, (struct sockaddr *)&address, &length) < 0) {
            close(socket_fd);
            return -1;
        }
        *bound_port = ntohs(address.sin6_port);
    }
    if (config->type == SOCK_STREAM && listen(socket_fd, 1) < 0) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

static void acknowledge(const char *message) {
    if (printf("%s\n", message) < 0 || fflush(stdout) != 0) {
        exit(2);
    }
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        return 9;
    }
    struct socket_config config = {
        .family = strcmp(argv[1], "tcp6") == 0 || strcmp(argv[1], "udp6") == 0
                      ? AF_INET6
                      : AF_INET,
        .type = strcmp(argv[1], "udp4") == 0 || strcmp(argv[1], "udp6") == 0
                    ? SOCK_DGRAM
                    : SOCK_STREAM,
        .wildcard = strcmp(argv[2], "wildcard") == 0,
        .ipv6_only = strcmp(argv[3], "default") == 0
                         ? -1
                         : strcmp(argv[3], "v6only") == 0,
        .count = (unsigned int)strtoul(argv[4], NULL, 10),
    };
    if ((strcmp(argv[1], "tcp4") != 0 && strcmp(argv[1], "tcp6") != 0 &&
         strcmp(argv[1], "udp4") != 0 && strcmp(argv[1], "udp6") != 0) ||
        (strcmp(argv[2], "exact") != 0 && strcmp(argv[2], "wildcard") != 0) ||
        (strcmp(argv[3], "default") != 0 && strcmp(argv[3], "v6only") != 0 &&
         strcmp(argv[3], "dual") != 0) ||
        config.count == 0 || config.count > 2 ||
        (config.family != AF_INET6 && strcmp(argv[3], "default") != 0)) {
        return 10;
    }
    if (strcmp(argv[3], "dual") == 0) {
        config.ipv6_only = 0;
    }

    unsigned long requested_port = argc == 6 ? strtoul(argv[5], NULL, 10) : 0;
    if (requested_port > 65535 || (argc == 6 && requested_port == 0)) {
        return 11;
    }
    unsigned short port = (unsigned short)requested_port;
    int socket_fds[2] = {-1, -1};
    for (unsigned int index = 0; index < config.count; index++) {
        socket_fds[index] = bind_socket(&config, port, &port);
        if (socket_fds[index] < 0) {
            while (index > 0) {
                index--;
                close(socket_fds[index]);
            }
            return 1;
        }
    }
    if (socket_fds[0] < 0) {
        return 1;
    }

    if (printf("READY %u\n", port) < 0 || fflush(stdout) != 0) {
        for (unsigned int index = 0; index < config.count; index++) {
            close(socket_fds[index]);
        }
        return 2;
    }

    char command[32];
    while (fgets(command, sizeof(command), stdin) != NULL) {
        command[strcspn(command, "\r\n")] = '\0';
        if (strcmp(command, "CLOSE") == 0) {
            for (unsigned int index = 0; index < config.count; index++) {
                if (socket_fds[index] < 0 || close(socket_fds[index]) != 0) {
                    return 3;
                }
                socket_fds[index] = -1;
            }
            acknowledge("CLOSE");
        } else if (strcmp(command, "REBIND") == 0) {
            for (unsigned int index = 0; index < config.count; index++) {
                if (socket_fds[index] >= 0) {
                    return 4;
                }
                socket_fds[index] = bind_socket(&config, port, &port);
                if (socket_fds[index] < 0) {
                    return 5;
                }
            }
            acknowledge("REBIND");
        } else if (strcmp(command, "EXIT") == 0) {
            for (unsigned int index = 0; index < config.count; index++) {
                if (socket_fds[index] >= 0 && close(socket_fds[index]) != 0) {
                    return 6;
                }
            }
            acknowledge("EXIT");
            return 0;
        } else {
            return 7;
        }
    }

    for (unsigned int index = 0; index < config.count; index++) {
        if (socket_fds[index] >= 0) {
            close(socket_fds[index]);
        }
    }
    return 8;
}
