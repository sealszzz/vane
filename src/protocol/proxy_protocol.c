#include "vane/proxy_protocol.h"

#include <arpa/inet.h>
#include <string.h>

static const uint8_t signature[12] = {
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
};

static bool v4_mapped_to_v4(const struct vane_addr *in,
                            struct vane_addr *out) {
    if (in->storage.ss_family != AF_INET6) return false;
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)&in->storage;
    if (!IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) return false;
    memset(out, 0, sizeof(*out));
    struct sockaddr_in *a4 = (struct sockaddr_in *)&out->storage;
    a4->sin_family = AF_INET;
    a4->sin_port = a6->sin6_port;
    memcpy(&a4->sin_addr, &a6->sin6_addr.s6_addr[12], 4);
    out->len = (socklen_t)sizeof(*a4);
    return true;
}

bool vane_proxy_v2_encode(const struct vane_addr *source,
                            const struct vane_addr *destination,
                            enum vane_proxy_transport transport,
                            struct vane_proxy_header *out,
                            struct vane_error *err) {
    if (source == NULL || destination == NULL || out == NULL) {
        vane_error_set(err, "PROXY protocol address is missing");
        return false;
    }
    struct vane_addr src = *source, dst = *destination, tmp;
    if (v4_mapped_to_v4(&src, &tmp)) src = tmp;
    if (v4_mapped_to_v4(&dst, &tmp)) dst = tmp;
    if (src.storage.ss_family != dst.storage.ss_family) {
        vane_error_set(err, "PROXY protocol source/destination families differ");
        return false;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->bytes, signature, sizeof(signature));
    out->bytes[12] = 0x21; /* version 2, PROXY */
    uint8_t proto = transport == VANE_PROXY_STREAM ? 0x01U : 0x02U;
    if (src.storage.ss_family == AF_INET) {
        out->bytes[13] = (uint8_t)(0x10U | proto);
        out->bytes[14] = 0;
        out->bytes[15] = 12;
        const struct sockaddr_in *s = (const struct sockaddr_in *)&src.storage;
        const struct sockaddr_in *d = (const struct sockaddr_in *)&dst.storage;
        memcpy(out->bytes + 16, &s->sin_addr, 4);
        memcpy(out->bytes + 20, &d->sin_addr, 4);
        memcpy(out->bytes + 24, &s->sin_port, 2);
        memcpy(out->bytes + 26, &d->sin_port, 2);
        out->len = 28;
        return true;
    }
    if (src.storage.ss_family == AF_INET6) {
        out->bytes[13] = (uint8_t)(0x20U | proto);
        out->bytes[14] = 0;
        out->bytes[15] = 36;
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)&src.storage;
        const struct sockaddr_in6 *d = (const struct sockaddr_in6 *)&dst.storage;
        memcpy(out->bytes + 16, &s->sin6_addr, 16);
        memcpy(out->bytes + 32, &d->sin6_addr, 16);
        memcpy(out->bytes + 48, &s->sin6_port, 2);
        memcpy(out->bytes + 50, &d->sin6_port, 2);
        out->len = 52;
        return true;
    }
    vane_error_set(err, "PROXY protocol supports only IPv4/IPv6");
    return false;
}
