#ifndef VANE_LINUX_NET_H
#define VANE_LINUX_NET_H

#include "vane/address.h"

#include <sys/socket.h>

#define VANE_UDP_CONTROL_SIZE 256U

struct vane_udp_meta {
    struct vane_addr peer;
    struct vane_addr local;
    uint8_t tclass;
    bool has_tclass;
    uint16_t gro_segment_size;
    bool has_gro;
};

int vane_socket_create_listener(const struct vane_addr *address,
                                  int type, int protocol, int backlog,
                                  size_t recv_buffer, size_t send_buffer,
                                  struct vane_error *err);
int vane_udp_enable_metadata(int fd, int family, bool enable_gro,
                               struct vane_error *err);
bool vane_udp_parse_meta(const struct msghdr *msg,
                           const struct vane_addr *bound,
                           struct vane_udp_meta *meta,
                           struct vane_error *err);
bool vane_udp_set_ancillary(struct msghdr *msg, size_t control_capacity,
                              int family, const struct vane_addr *local,
                              const uint8_t *tclass,
                              const uint16_t *segment_size,
                              struct vane_error *err);
ssize_t vane_udp_recvmsg(int fd, void *buf, size_t buf_len,
                           const struct vane_addr *bound,
                           struct vane_udp_meta *meta,
                           struct vane_error *err);
ssize_t vane_udp_sendmsg(int fd, int family,
                           const struct iovec *iov, size_t iov_count,
                           const struct vane_addr *peer,
                           const struct vane_addr *local,
                           const uint8_t *tclass,
                           const uint16_t *segment_size,
                           struct vane_error *err);

#endif
