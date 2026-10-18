#ifndef VANE_PROXY_PROTOCOL_H
#define VANE_PROXY_PROTOCOL_H

#include "vane/address.h"

enum vane_proxy_transport {
    VANE_PROXY_STREAM = 1,
    VANE_PROXY_DGRAM = 2,
};

struct vane_proxy_header {
    uint8_t bytes[64];
    size_t len;
};

bool vane_proxy_v2_encode(const struct vane_addr *source,
                            const struct vane_addr *destination,
                            enum vane_proxy_transport transport,
                            struct vane_proxy_header *out,
                            struct vane_error *err);

#endif
