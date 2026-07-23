#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

typedef int (*open_function)(const char *, int, ...);

static volatile sig_atomic_t fault_state;

static void arm_fault(int signal_number) {
    (void)signal_number;
    fault_state = 1;
}

__attribute__((constructor)) static void install_fault_control(void) {
    signal(SIGUSR2, arm_fault);
}

static int fail_once(const char *path) {
    if (path == NULL || strcmp(path, "/proc/net/tcp") != 0) {
        return 0;
    }
    if (fault_state == 2) {
        fault_state = 0;
        kill(getpid(), SIGINT);
    }
    if (fault_state == 1) {
        fault_state = 2;
        return 1;
    }
    return 0;
}

static int call_open(const char *symbol, const char *path, int flags, va_list arguments) {
    open_function native_open = (open_function)dlsym(RTLD_NEXT, symbol);
    if (native_open == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (fail_once(path)) {
        errno = EACCES;
        return -1;
    }
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        mode_t mode = va_arg(arguments, mode_t);
        return native_open(path, flags, mode);
    }
    return native_open(path, flags);
}

int open(const char *path, int flags, ...) {
    va_list arguments;
    va_start(arguments, flags);
    int result = call_open("open", path, flags, arguments);
    va_end(arguments);
    return result;
}

int open64(const char *path, int flags, ...) {
    va_list arguments;
    va_start(arguments, flags);
    int result = call_open("open64", path, flags, arguments);
    va_end(arguments);
    return result;
}
