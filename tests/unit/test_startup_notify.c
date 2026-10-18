/* White-box access keeps the notification helper private in the public API. */
#include "../../src/core/runtime.c"

#include <assert.h>

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol);
ssize_t __wrap_sendto(int fd, const void *data, size_t len, int flags,
                      const struct sockaddr *address, socklen_t address_len);

static const char *expected_path;
static size_t socket_calls, send_calls;
static bool fail_send;

int __wrap_socket(int domain, int type, int protocol) {
    assert(domain == AF_UNIX);
    assert(type == (SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC));
    assert(protocol == 0);
    socket_calls++;
    return __real_socket(AF_INET, type, protocol);
}

ssize_t __wrap_sendto(int fd, const void *data, size_t len, int flags,
                      const struct sockaddr *address, socklen_t address_len) {
    assert(fd >= 0 && len == 7U && memcmp(data, "READY=1", 7U) == 0);
    assert(flags == MSG_NOSIGNAL && address->sa_family == AF_UNIX);
    const struct sockaddr_un *un = (const struct sockaddr_un *)address;
    size_t path_len = strlen(expected_path);
    if (expected_path[0] == '@') {
        assert(un->sun_path[0] == '\0');
        assert(memcmp(un->sun_path + 1, expected_path + 1, path_len - 1U) == 0);
        assert(address_len == offsetof(struct sockaddr_un, sun_path) + path_len);
    } else {
        assert(strcmp(un->sun_path, expected_path) == 0);
        assert(address_len == offsetof(struct sockaddr_un, sun_path) + path_len + 1U);
    }
    send_calls++;
    if (fail_send) { errno = ENOENT; return -1; }
    return (ssize_t)len;
}

int main(void) {
    struct vane_error err = {0};
    assert(unsetenv("NOTIFY_SOCKET") == 0);
    assert(notify_ready(&err) && socket_calls == 0U);
    expected_path = "/run/vane-test.sock";
    assert(setenv("NOTIFY_SOCKET", expected_path, 1) == 0);
    assert(notify_ready(&err) && socket_calls == 1U && send_calls == 1U);
    expected_path = "@vane-test";
    assert(setenv("NOTIFY_SOCKET", expected_path, 1) == 0);
    assert(notify_ready(&err) && socket_calls == 2U && send_calls == 2U);
    fail_send = true;
    assert(!notify_ready(&err));
    assert(strstr(err.message, "readiness notification") != NULL);
    assert(setenv("NOTIFY_SOCKET", "relative/path", 1) == 0);
    assert(!notify_ready(&err) && socket_calls == 3U);
    char too_long[256];
    memset(too_long, 'x', sizeof(too_long));
    too_long[0] = '/'; too_long[sizeof(too_long) - 1U] = '\0';
    assert(setenv("NOTIFY_SOCKET", too_long, 1) == 0);
    assert(!notify_ready(&err) && socket_calls == 3U);
    assert(unsetenv("NOTIFY_SOCKET") == 0);
    return 0;
}
