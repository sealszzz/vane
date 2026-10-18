#ifndef VANE_ADDRESS_H
#define VANE_ADDRESS_H

#include "vane/common.h"

#include <netinet/in.h>
#include <sys/socket.h>

struct vane_addr {
    struct sockaddr_storage storage;
    socklen_t len;
};

bool vane_addr_parse(const char *text, bool allow_port_zero,
                       struct vane_addr *out, struct vane_error *err);
const char *vane_addr_format(const struct vane_addr *addr,
                               char *buf, size_t buf_len);
uint16_t vane_addr_port(const struct vane_addr *addr);
bool vane_addr_equal(const struct vane_addr *a, const struct vane_addr *b);
bool vane_addr_is_ipv4(const struct vane_addr *addr);
bool vane_addr_is_ipv6(const struct vane_addr *addr);
bool vane_addr_is_wildcard(const struct vane_addr *addr);
bool vane_addr_is_dual_stack_wildcard(const struct vane_addr *addr);
int vane_addr_effective_family(const struct vane_addr *addr);
uint64_t vane_addr_hash(const struct vane_addr *addr, uint64_t seed);
bool vane_addr_from_sockaddr(const struct sockaddr *sa, socklen_t len,
                               struct vane_addr *out);

#endif
