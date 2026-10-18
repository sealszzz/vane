#include "vane/address.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_port(const char *text, bool allow_zero, uint16_t *out,
                       struct vane_error *err) {
    if (text == NULL || *text == '\0') {
        vane_error_set(err, "missing port");
        return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > 65535UL ||
        (!allow_zero && value == 0UL)) {
        vane_error_set(err, "invalid port: %s", text);
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

bool vane_addr_parse(const char *text, bool allow_port_zero,
                       struct vane_addr *out, struct vane_error *err) {
    if (text == NULL || out == NULL) {
        vane_error_set(err, "address is missing");
        return false;
    }
    memset(out, 0, sizeof(*out));

    if (text[0] == '[') {
        const char *close = strchr(text, ']');
        if (close == NULL || close[1] != ':') {
            vane_error_set(err, "invalid IPv6 socket address: %s", text);
            return false;
        }
        size_t host_len = (size_t)(close - text - 1);
        if (host_len == 0 || host_len >= INET6_ADDRSTRLEN) {
            vane_error_set(err, "invalid IPv6 address: %s", text);
            return false;
        }
        char host[INET6_ADDRSTRLEN];
        memcpy(host, text + 1, host_len);
        host[host_len] = '\0';
        uint16_t port = 0;
        if (!parse_port(close + 2, allow_port_zero, &port, err)) {
            return false;
        }
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&out->storage;
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &a6->sin6_addr) != 1) {
            vane_error_set(err, "invalid IPv6 address: %s", host);
            return false;
        }
        out->len = (socklen_t)sizeof(*a6);
        return true;
    }

    const char *colon = strrchr(text, ':');
    if (colon == NULL || strchr(text, ':') != colon) {
        vane_error_set(err,
                         "socket address must be IPv4:port or [IPv6]:port: %s",
                         text);
        return false;
    }
    size_t host_len = (size_t)(colon - text);
    if (host_len == 0 || host_len >= INET_ADDRSTRLEN) {
        vane_error_set(err, "invalid IPv4 address: %s", text);
        return false;
    }
    char host[INET_ADDRSTRLEN];
    memcpy(host, text, host_len);
    host[host_len] = '\0';
    uint16_t port = 0;
    if (!parse_port(colon + 1, allow_port_zero, &port, err)) {
        return false;
    }
    struct sockaddr_in *a4 = (struct sockaddr_in *)&out->storage;
    a4->sin_family = AF_INET;
    a4->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a4->sin_addr) != 1) {
        vane_error_set(err, "invalid IPv4 address: %s", host);
        return false;
    }
    out->len = (socklen_t)sizeof(*a4);
    return true;
}

const char *vane_addr_format(const struct vane_addr *addr,
                               char *buf, size_t buf_len) {
    if (addr == NULL || buf == NULL || buf_len == 0) {
        return NULL;
    }
    char ip[INET6_ADDRSTRLEN];
    const void *src = NULL;
    uint16_t port = 0;
    if (addr->storage.ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)&addr->storage;
        src = &a4->sin_addr;
        port = ntohs(a4->sin_port);
        if (inet_ntop(AF_INET, src, ip, sizeof(ip)) == NULL) {
            return NULL;
        }
        (void)snprintf(buf, buf_len, "%s:%u", ip, (unsigned)port);
        return buf;
    }
    if (addr->storage.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)&addr->storage;
        src = &a6->sin6_addr;
        port = ntohs(a6->sin6_port);
        if (inet_ntop(AF_INET6, src, ip, sizeof(ip)) == NULL) {
            return NULL;
        }
        (void)snprintf(buf, buf_len, "[%s]:%u", ip, (unsigned)port);
        return buf;
    }
    (void)snprintf(buf, buf_len, "<invalid>");
    return buf;
}

uint16_t vane_addr_port(const struct vane_addr *addr) {
    if (addr->storage.ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)&addr->storage)->sin_port);
    }
    if (addr->storage.ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&addr->storage)->sin6_port);
    }
    return 0;
}

bool vane_addr_equal(const struct vane_addr *a, const struct vane_addr *b) {
    if (a == NULL || b == NULL || a->storage.ss_family != b->storage.ss_family) {
        return false;
    }
    if (a->storage.ss_family == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)&a->storage;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)&b->storage;
        return aa->sin_port == bb->sin_port &&
               aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }
    if (a->storage.ss_family == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)&a->storage;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)&b->storage;
        return aa->sin6_port == bb->sin6_port && aa->sin6_scope_id == bb->sin6_scope_id &&
               memcmp(&aa->sin6_addr, &bb->sin6_addr, sizeof(aa->sin6_addr)) == 0;
    }
    return false;
}

bool vane_addr_is_ipv4(const struct vane_addr *addr) {
    return addr != NULL && addr->storage.ss_family == AF_INET;
}

bool vane_addr_is_ipv6(const struct vane_addr *addr) {
    return addr != NULL && addr->storage.ss_family == AF_INET6;
}

bool vane_addr_is_wildcard(const struct vane_addr *addr) {
    if (vane_addr_is_ipv4(addr)) {
        return ((const struct sockaddr_in *)&addr->storage)->sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if (vane_addr_is_ipv6(addr)) {
        return IN6_IS_ADDR_UNSPECIFIED(&((const struct sockaddr_in6 *)&addr->storage)->sin6_addr);
    }
    return false;
}

bool vane_addr_is_dual_stack_wildcard(const struct vane_addr *addr) {
    return vane_addr_is_ipv6(addr) && vane_addr_is_wildcard(addr);
}

int vane_addr_effective_family(const struct vane_addr *addr) {
    if (addr == NULL) return AF_UNSPEC;
    if (addr->storage.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)&addr->storage;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) return AF_INET;
    }
    return addr->storage.ss_family;
}

static uint64_t mix64(uint64_t x) {
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

uint64_t vane_addr_hash(const struct vane_addr *addr, uint64_t seed) {
    uint64_t h = mix64(seed ^ (uint64_t)addr->storage.ss_family);
    if (addr->storage.ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)&addr->storage;
        h ^= mix64((uint64_t)a4->sin_addr.s_addr << 16 | a4->sin_port);
    } else if (addr->storage.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)&addr->storage;
        uint64_t words[2];
        memcpy(words, &a6->sin6_addr, sizeof(words));
        h ^= mix64(words[0]);
        h ^= mix64(words[1]);
        h ^= mix64((uint64_t)a6->sin6_port | ((uint64_t)a6->sin6_scope_id << 16));
    }
    return mix64(h);
}


bool vane_addr_from_sockaddr(const struct sockaddr *sa, socklen_t len,
                               struct vane_addr *out) {
    if (sa == NULL || out == NULL) return false;
    memset(out, 0, sizeof(*out));
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        memcpy(&out->storage, sa, sizeof(struct sockaddr_in));
        out->len = (socklen_t)sizeof(struct sockaddr_in);
        return true;
    }
    if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        memcpy(&out->storage, sa, sizeof(struct sockaddr_in6));
        out->len = (socklen_t)sizeof(struct sockaddr_in6);
        return true;
    }
    return false;
}
