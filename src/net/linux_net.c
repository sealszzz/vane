#include "vane/linux_net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/udp.h>
#include <limits.h>
#include <sys/uio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <unistd.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

static bool set_int_opt(int fd, int level, int name, int value,
                        const char *label, struct vane_error *err) {
    if (setsockopt(fd, level, name, &value, (socklen_t)sizeof(value)) != 0) {
        vane_error_set(err, "%s: %s", label, strerror(errno));
        return false;
    }
    return true;
}

int vane_socket_create_listener(const struct vane_addr *address,
                                  int type, int protocol, int backlog,
                                  size_t recv_buffer, size_t send_buffer,
                                  struct vane_error *err) {
    int family = address->storage.ss_family;
    int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    if (fd < 0) {
        vane_error_set(err, "socket: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    if (!set_int_opt(fd, SOL_SOCKET, SO_REUSEADDR, one, "SO_REUSEADDR", err) ||
        !set_int_opt(fd, SOL_SOCKET, SO_REUSEPORT, one, "SO_REUSEPORT", err)) goto fail;
    if (family == AF_INET6 &&
        !set_int_opt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0, "IPV6_V6ONLY", err)) goto fail;
    if (recv_buffer > (size_t)INT_MAX || send_buffer > (size_t)INT_MAX) {
        vane_error_set(err, "socket buffer size exceeds INT_MAX");
        goto fail;
    }
    if (recv_buffer != 0U &&
        !set_int_opt(fd, SOL_SOCKET, SO_RCVBUF, (int)recv_buffer,
                     "SO_RCVBUF", err)) goto fail;
    if (send_buffer != 0U &&
        !set_int_opt(fd, SOL_SOCKET, SO_SNDBUF, (int)send_buffer,
                     "SO_SNDBUF", err)) goto fail;
    if (bind(fd, (const struct sockaddr *)&address->storage, address->len) != 0) {
        vane_error_set(err, "bind: %s", strerror(errno));
        goto fail;
    }
    if (type == SOCK_STREAM && listen(fd, backlog) != 0) {
        vane_error_set(err, "listen: %s", strerror(errno));
        goto fail;
    }
    return fd;
fail:
    close(fd);
    return -1;
}

int vane_udp_enable_metadata(int fd, int family, bool enable_gro,
                               struct vane_error *err) {
    int one = 1;
    if (family == AF_INET) {
        if (!set_int_opt(fd, IPPROTO_IP, IP_PKTINFO, one, "IP_PKTINFO", err) ||
            !set_int_opt(fd, IPPROTO_IP, IP_RECVTOS, one, "IP_RECVTOS", err)) return -1;
    } else if (family == AF_INET6) {
        if (!set_int_opt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, one, "IPV6_RECVPKTINFO", err) ||
            !set_int_opt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, one, "IPV6_RECVTCLASS", err) ||
            !set_int_opt(fd, IPPROTO_IP, IP_RECVTOS, one, "IP_RECVTOS", err)) return -1;
    } else {
        vane_error_set(err, "unsupported UDP family");
        return -1;
    }
    if (enable_gro && setsockopt(fd, SOL_UDP, UDP_GRO, &one, (socklen_t)sizeof(one)) != 0) {
        if (errno != ENOPROTOOPT && errno != EOPNOTSUPP && errno != EINVAL) {
            vane_error_set(err, "UDP_GRO: %s", strerror(errno));
            return -1;
        }
        return 0;
    }
    return enable_gro ? 1 : 0;
}

static void set_local_ip(struct vane_addr *local, const void *addr, int family) {
    if (family == AF_INET) {
        uint16_t port = 0;
        if (local->storage.ss_family == AF_INET) {
            port = ((const struct sockaddr_in *)&local->storage)->sin_port;
        } else if (local->storage.ss_family == AF_INET6) {
            port = ((const struct sockaddr_in6 *)&local->storage)->sin6_port;
        } else {
            return;
        }
        struct sockaddr_in v4 = {0};
        v4.sin_family = AF_INET;
        v4.sin_port = port;
        v4.sin_addr = *(const struct in_addr *)addr;
        memset(&local->storage, 0, sizeof(local->storage));
        memcpy(&local->storage, &v4, sizeof(v4));
        local->len = (socklen_t)sizeof(v4);
    } else if (family == AF_INET6 && local->storage.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)&local->storage)->sin6_addr = *(const struct in6_addr *)addr;
    }
}

bool vane_udp_parse_meta(const struct msghdr *msg,
                           const struct vane_addr *bound,
                           struct vane_udp_meta *meta,
                           struct vane_error *err) {
    if (msg == NULL || bound == NULL || meta == NULL) {
        errno = EINVAL;
        vane_error_set(err, "UDP metadata input is missing");
        return false;
    }
    memset(meta, 0, sizeof(*meta));
    meta->local = *bound;
    if (!vane_addr_from_sockaddr((const struct sockaddr *)msg->msg_name,
                                   msg->msg_namelen, &meta->peer)) {
        errno = EAFNOSUPPORT;
        vane_error_set(err, "unsupported UDP peer address");
        return false;
    }
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR((struct msghdr *)(uintptr_t)msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR((struct msghdr *)(uintptr_t)msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(cmsg), sizeof(pi));
            set_local_ip(&meta->local, &pi.ipi_addr, AF_INET);
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
                   cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
            struct in6_pktinfo pi6;
            memcpy(&pi6, CMSG_DATA(cmsg), sizeof(pi6));
            set_local_ip(&meta->local, &pi6.ipi6_addr, AF_INET6);
        } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS &&
                   cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t data_len = cmsg->cmsg_len - CMSG_LEN(0);
            int value = 0;
            if (data_len >= sizeof(value)) {
                memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
            } else if (data_len >= sizeof(uint8_t)) {
                uint8_t byte = 0;
                memcpy(&byte, CMSG_DATA(cmsg), sizeof(byte));
                value = byte;
            } else {
                continue;
            }
            meta->tclass = (uint8_t)value;
            meta->has_tclass = true;
        } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
                   cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            int value = 0;
            memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
            meta->tclass = (uint8_t)value;
            meta->has_tclass = true;
        } else if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO &&
                   cmsg->cmsg_len >= CMSG_LEN(0)) {
            size_t data_len = cmsg->cmsg_len - CMSG_LEN(0);
            int value = 0;
            if (data_len >= sizeof(value)) {
                memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
            } else if (data_len >= sizeof(uint16_t)) {
                uint16_t value16 = 0;
                memcpy(&value16, CMSG_DATA(cmsg), sizeof(value16));
                value = value16;
            }
            if (value > 0 && value <= UINT16_MAX) {
                meta->gro_segment_size = (uint16_t)value;
                meta->has_gro = true;
            }
        }
    }
    return true;
}

ssize_t vane_udp_recvmsg(int fd, void *buf, size_t buf_len,
                           const struct vane_addr *bound,
                           struct vane_udp_meta *meta,
                           struct vane_error *err) {
    struct sockaddr_storage peer;
    struct iovec iov = {.iov_base = buf, .iov_len = buf_len};
    union {
        struct cmsghdr align;
        unsigned char bytes[VANE_UDP_CONTROL_SIZE];
    } control;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    memset(&peer, 0, sizeof(peer));
    msg.msg_name = &peer;
    msg.msg_namelen = (socklen_t)sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ENOBUFS)
            vane_error_set(err, "recvmsg: %s", strerror(errno));
        return n;
    }
    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || (size_t)n > buf_len) {
        errno = EMSGSIZE;
        vane_error_set(err, "UDP datagram/control metadata was truncated");
        return -1;
    }
    if (!vane_udp_parse_meta(&msg, bound, meta, err)) {
        return -1;
    }
    return n;
}

static bool append_cmsg(struct msghdr *msg, size_t control_cap,
                        int level, int type, const void *data, size_t data_len,
                        struct vane_error *err) {
    size_t used = msg->msg_controllen;
    size_t space = CMSG_SPACE(data_len);
    if (used > control_cap || space > control_cap - used) {
        vane_error_set(err, "UDP ancillary data buffer is too small");
        return false;
    }
    unsigned char *base = (unsigned char *)msg->msg_control + used;
    struct cmsghdr header = {
        .cmsg_len = CMSG_LEN(data_len),
        .cmsg_level = level,
        .cmsg_type = type,
    };
    memset(base, 0, space);
    memcpy(base, &header, sizeof(header));
    memcpy(base + CMSG_ALIGN(sizeof(struct cmsghdr)), data, data_len);
    msg->msg_controllen += space;
    return true;
}
bool vane_udp_set_ancillary(struct msghdr *msg, size_t control_capacity,
                              int family, const struct vane_addr *local,
                              const uint8_t *tclass,
                              const uint16_t *segment_size,
                              struct vane_error *err) {
    if (msg == NULL || msg->msg_control == NULL) {
        errno = EINVAL;
        vane_error_set(err, "UDP ancillary output is missing");
        return false;
    }
    msg->msg_controllen = 0;
    if (local != NULL) {
        if (local->storage.ss_family == AF_INET) {
            struct in_pktinfo pi = {0};
            pi.ipi_spec_dst = ((const struct sockaddr_in *)&local->storage)->sin_addr;
            if (!append_cmsg(msg, control_capacity, IPPROTO_IP, IP_PKTINFO,
                             &pi, sizeof(pi), err)) return false;
        } else if (local->storage.ss_family == AF_INET6) {
            struct in6_pktinfo pi6 = {0};
            pi6.ipi6_addr = ((const struct sockaddr_in6 *)&local->storage)->sin6_addr;
            if (!append_cmsg(msg, control_capacity, IPPROTO_IPV6, IPV6_PKTINFO,
                             &pi6, sizeof(pi6), err)) return false;
        } else {
            errno = EAFNOSUPPORT;
            vane_error_set(err, "unsupported UDP local address family");
            return false;
        }
    }
    if (family != AF_INET && family != AF_INET6) {
        errno = EAFNOSUPPORT;
        vane_error_set(err, "unsupported UDP send family");
        return false;
    }
    if (tclass != NULL) {
        int value = *tclass;
        int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        int type = family == AF_INET ? IP_TOS : IPV6_TCLASS;
        if (!append_cmsg(msg, control_capacity, level, type,
                         &value, sizeof(value), err)) return false;
    }
    if (segment_size != NULL) {
        if (*segment_size == 0) {
            errno = EINVAL;
            vane_error_set(err, "UDP_SEGMENT size is zero");
            return false;
        }
        if (!append_cmsg(msg, control_capacity, SOL_UDP, UDP_SEGMENT,
                         segment_size, sizeof(*segment_size), err)) return false;
    }
    return true;
}


ssize_t vane_udp_sendmsg(int fd, int family,
                           const struct iovec *iov, size_t iov_count,
                           const struct vane_addr *peer,
                           const struct vane_addr *local,
                           const uint8_t *tclass,
                           const uint16_t *segment_size,
                           struct vane_error *err) {
    if (iov_count == 0 || iov_count > IOV_MAX) {
        errno = EINVAL;
        vane_error_set(err, "invalid UDP iovec count");
        return -1;
    }
    union {
        struct cmsghdr align;
        unsigned char bytes[VANE_UDP_CONTROL_SIZE];
    } control;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    msg.msg_iov = (struct iovec *)(uintptr_t)iov;
    msg.msg_iovlen = iov_count;
    if (peer != NULL) {
        msg.msg_name = (void *)(uintptr_t)&peer->storage;
        msg.msg_namelen = peer->len;
    }
    msg.msg_control = control.bytes;
    int address_family = peer != NULL ? vane_addr_effective_family(peer) :
                         (local != NULL ? vane_addr_effective_family(local) : family);
    if (!vane_udp_set_ancillary(&msg, sizeof(control.bytes), address_family,
                                  local, tclass, segment_size, err)) {
        return -1;
    }
    ssize_t sent;
    do {
        sent = sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent;
}
