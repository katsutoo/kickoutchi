#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static int should_fail(const char *path) {
    const char *state = getenv("KICKOUTCHI_QA_FAULT_STATE");
    const char *plan = getenv("KICKOUTCHI_QA_FAULT_PLAN");
    int fd, attempt = 0, fail = 0;
    char value[32] = {0};

    if (!state || !plan || !path || strcmp(path, "/proc/net/tcp") != 0)
        return 0;
    fd = open(state, O_RDWR | O_CREAT, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    ssize_t count = read(fd, value, sizeof(value) - 1);
    if (count > 0) attempt = atoi(value);
    attempt++;
    for (const char *cursor = plan; *cursor; cursor++) {
        char *end;
        long selected = strtol(cursor, &end, 10);
        if (end != cursor && selected == attempt) fail = 1;
        cursor = end == cursor ? cursor : end - 1;
    }
    snprintf(value, sizeof(value), "%d", attempt);
    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);
    write(fd, value, strlen(value));
    fsync(fd);
    flock(fd, LOCK_UN);
    close(fd);
    return fail;
}

int open64(const char *path, int flags, ...) {
    static int (*real_open64)(const char *, int, ...) = NULL;
    mode_t mode = 0;
    if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (should_fail(path)) { errno = EACCES; return -1; }
    return flags & O_CREAT ? real_open64(path, flags, mode) : real_open64(path, flags);
}

int open(const char *path, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    mode_t mode = 0;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (should_fail(path)) { errno = EACCES; return -1; }
    return flags & O_CREAT ? real_open(path, flags, mode) : real_open(path, flags);
}
