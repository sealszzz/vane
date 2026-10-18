#include "udp_internal.h"

#include "vane/log.h"
#include "vane/proxy_protocol.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/uio.h>

bool udp_gso_error_disables(int error_number) {
    return error_number == EIO || error_number == EINVAL ||
           error_number == EMSGSIZE || error_number == ENOPROTOOPT ||
           error_number == EOPNOTSUPP || error_number == ENOSYS;
}

bool udp_gso_error_allows_fallback(int error_number) {
    /* ENOBUFS is backpressure, not an offload-compatibility failure.  Retrying
     * the same train as individual datagrams only adds work while the socket
     * is already full. */
    return udp_gso_error_disables(error_number);
}

static bool send_upstream_individual(struct udp_flow *flow,
                                     const uint8_t *data, size_t len,
                                     uint16_t segment_size,
                                     uint8_t tclass, bool has_tclass);

static bool prepare_down_message(struct udp_worker *worker, size_t index,
                                 const struct udp_down_item *item,
                                 size_t offset, size_t len, bool use_gso) {
    struct mmsghdr *mmsg = &worker->tx_msgs[index];
    struct iovec *iov = &worker->tx_iov[index];
    unsigned char *control = worker->tx_controls + index * VANE_UDP_CONTROL_SIZE;
    memset(mmsg, 0, sizeof(*mmsg));
    memset(control, 0, VANE_UDP_CONTROL_SIZE);
    iov->iov_base = item->data + offset;
    iov->iov_len = len;
    mmsg->msg_hdr.msg_name = (void *)(uintptr_t)&item->peer.storage;
    mmsg->msg_hdr.msg_namelen = item->peer.len;
    mmsg->msg_hdr.msg_iov = iov;
    mmsg->msg_hdr.msg_iovlen = 1;
    mmsg->msg_hdr.msg_control = control;
    const uint8_t *tclass = item->has_tclass ? &item->tclass : NULL;
    const uint16_t *segment = use_gso ? &item->segment_size : NULL;
    struct vane_error err = {0};
    return vane_udp_set_ancillary(&mmsg->msg_hdr, VANE_UDP_CONTROL_SIZE,
                                    vane_addr_effective_family(&item->peer),
                                    &item->local, tclass, segment, &err);
}

void udp_downstream_flush(struct udp_worker *worker) {
    if (worker->down_count == 0U) return;
    /* The runtime caps send_batch at 256. Each window can contain either
     * complete GSO trains or individual original datagrams. Storage belongs
     * to down[] until every window is consumed, including partial sends. */
    size_t next_item[256];
    size_t next_offset[256];
    size_t limit = VANE_MIN(worker->down_capacity, VANE_ARRAY_LEN(next_item));
    if (limit == 0U) { worker->down_count = 0U; return; }
    size_t item_index = 0U, item_offset = 0U;
    while (item_index < worker->down_count) {
        size_t scan_index = item_index, scan_offset = item_offset;
        size_t prepared = 0U;
        bool first_gso = false;
        while (scan_index < worker->down_count && prepared < limit) {
            const struct udp_down_item *item = &worker->down[scan_index];
            bool segmented = item->has_segment && item->segment_size != 0U &&
                             item->len > item->segment_size;
            bool use_gso = segmented && worker->public_gso_enabled;
            size_t len = item->len - scan_offset;
            if (segmented && !use_gso)
                len = VANE_MIN(len, (size_t)item->segment_size);
            if (!prepare_down_message(worker, prepared, item,
                                       scan_offset, len, use_gso))
                break;
            if (prepared == 0U) first_gso = use_gso;
            scan_offset += len;
            if (scan_offset == item->len) {
                scan_index++;
                scan_offset = 0U;
            }
            next_item[prepared] = scan_index;
            next_offset[prepared] = scan_offset;
            prepared++;
        }
        if (prepared == 0U) {
            LOG_WARN("UDP worker %zu downstream metadata preparation failed",
                     worker->args->worker_index);
            item_index++;
            item_offset = 0U;
            continue;
        }
        int sent;
        do {
            sent = sendmmsg(worker->public_fd, worker->tx_msgs,
                            (unsigned int)prepared, MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent > 0) {
            size_t last = (size_t)sent - 1U;
            item_index = next_item[last];
            item_offset = next_offset[last];
            /* A partial return does not preserve the failed message's errno.
             * Retry the remainder as a batch to observe its actual error. */
            continue;
        }
        int saved = sent == 0 ? EIO : errno;
        if (saved == EAGAIN || saved == EWOULDBLOCK || saved == ENOBUFS) {
            LOG_TRACE("UDP worker %zu downstream batch=%zu dropped: %s",
                      worker->args->worker_index, prepared, strerror(saved));
            break;
        }
        if (first_gso && udp_gso_error_disables(saved)) {
            LOG_WARN("UDP worker %zu public UDP_SEGMENT disabled: %s",
                     worker->args->worker_index, strerror(saved));
            worker->public_gso_enabled = false;
            continue;
        }
        LOG_WARN("UDP worker %zu downstream send failed: %s (datagram dropped)",
                 worker->args->worker_index, strerror(saved));
        item_index = next_item[0];
        item_offset = next_offset[0];
    }
    worker->down_count = 0U;
}

static bool queue_down_train(struct udp_worker *worker, const struct udp_flow *flow,
                             const uint8_t *data, size_t len,
                             uint16_t segment_size, bool has_segment,
                             uint8_t tclass, bool has_tclass) {
    if (len > UDP_MAX_PACKET) return false;
    if (worker->down_count == worker->down_capacity) udp_downstream_flush(worker);
    if (worker->down_count == worker->down_capacity) return false;
    struct udp_down_item *item = &worker->down[worker->down_count];
    item->data = worker->down_storage + worker->down_count * UDP_MAX_PACKET;
    memcpy(item->data, data, len);
    item->len = len;
    item->segment_size = segment_size;
    item->has_segment = has_segment;
    item->peer = flow->key.client;
    item->local = flow->key.local;
    item->tclass = tclass;
    item->has_tclass = has_tclass;
    worker->down_count++;
    return true;
}

void udp_downstream_queue(struct udp_worker *worker,
                          const struct udp_flow *flow,
                          const uint8_t *data, size_t len,
                          uint16_t gro_segment_size,
                          uint8_t tclass, bool has_tclass) {
    if (gro_segment_size == 0 || len <= gro_segment_size) {
        (void)queue_down_train(worker, flow, data, len, 0, false, tclass, has_tclass);
        return;
    }
    size_t offset = 0;
    while (offset < len) {
        size_t remaining = len - offset;
        size_t full_segments = remaining / gro_segment_size;
        size_t max_segments = VANE_MIN((size_t)UDP_GSO_MAX_SEGMENTS,
                                         UDP_GSO_SAFE_BYTES / gro_segment_size);
        if (max_segments == 0) max_segments = 1;
        size_t segments = VANE_MIN(full_segments, max_segments);
        size_t train_len;
        if (segments == 0) {
            train_len = remaining;
        } else {
            train_len = segments * gro_segment_size;
            if (train_len < remaining && segments < max_segments &&
                remaining - train_len < gro_segment_size)
                train_len = remaining;
        }
        bool gso = train_len > gro_segment_size;
        if (!queue_down_train(worker, flow, data + offset, train_len,
                              gro_segment_size, gso, tclass, has_tclass)) return;
        offset += train_len;
    }
}

static bool send_plain_train(int fd, int family,
                             const uint8_t *data, size_t len,
                             uint16_t segment_size, bool use_gso,
                             uint8_t tclass, bool has_tclass,
                             struct vane_error *err) {
    struct iovec iov = {.iov_base = (void *)(uintptr_t)data, .iov_len = len};
    const uint8_t *tc = has_tclass ? &tclass : NULL;
    const uint16_t *seg = use_gso ? &segment_size : NULL;
    ssize_t n = vane_udp_sendmsg(fd, family, &iov, 1, NULL, NULL, tc, seg, err);
    if (n == (ssize_t)len) return true;
    if (n >= 0) errno = EIO;
    return false;
}

static bool send_proxy_train(const struct udp_flow *flow,
                             const uint8_t *data, size_t len,
                             uint16_t segment_size, bool use_gso,
                             uint8_t tclass, bool has_tclass,
                             struct vane_error *err) {
    struct vane_proxy_header header;
    if (!vane_proxy_v2_encode(&flow->key.client, &flow->key.local,
                                VANE_PROXY_DGRAM, &header, err)) return false;
    if (len == 0U) {
        struct iovec iov = {.iov_base = header.bytes, .iov_len = header.len};
        const uint8_t *tc = has_tclass ? &tclass : NULL;
        ssize_t sent = vane_udp_sendmsg(flow->upstream_fd,
                                          flow->target->location.storage.ss_family,
                                          &iov, 1, NULL, NULL, tc, NULL, err);
        if (sent == (ssize_t)header.len) return true;
        if (sent >= 0) errno = EIO;
        return false;
    }
    if (segment_size == 0U) {
        errno = EINVAL;
        vane_error_set(err, "UDP segment size is zero");
        return false;
    }
    size_t count = (len + segment_size - 1U) / segment_size;
    if (count > UDP_GSO_MAX_SEGMENTS) {
        errno = EMSGSIZE;
        vane_error_set(err, "UDP GSO train exceeds the segment limit");
        return false;
    }
    struct iovec iov[UDP_GSO_MAX_SEGMENTS * 2U];
    size_t offset = 0, iov_count = 0, expected = 0;
    while (offset < len) {
        size_t n = VANE_MIN((size_t)segment_size, len - offset);
        iov[iov_count++] = (struct iovec){.iov_base = header.bytes, .iov_len = header.len};
        iov[iov_count++] = (struct iovec){
            .iov_base = (void *)(uintptr_t)(data + offset),
            .iov_len = n,
        };
        expected += header.len + n;
        offset += n;
    }
    size_t wire_size = header.len + segment_size;
    if (use_gso && wire_size > UINT16_MAX) {
        errno = EMSGSIZE;
        vane_error_set(err, "UDP PROXY segment exceeds UINT16_MAX");
        return false;
    }
    uint16_t wire_segment = (uint16_t)wire_size;
    const uint8_t *tc = has_tclass ? &tclass : NULL;
    const uint16_t *seg = use_gso ? &wire_segment : NULL;
    ssize_t sent = vane_udp_sendmsg(flow->upstream_fd,
                                      flow->target->location.storage.ss_family,
                                      iov, iov_count, NULL, NULL, tc, seg, err);
    if (sent == (ssize_t)expected) return true;
    if (sent >= 0) errno = EIO;
    return false;
}

static bool send_upstream_views_individual(struct udp_flow *flow,
                                           const uint8_t *const *packets,
                                           size_t count, size_t segment_size,
                                           uint8_t tclass, bool has_tclass) {
    for (size_t i = 0; i < count; i++) {
        if (!send_upstream_individual(flow, packets[i], segment_size,
                                      (uint16_t)segment_size,
                                      tclass, has_tclass))
            return false;
    }
    return true;
}

bool udp_send_upstream_views(struct udp_flow *flow,
                             const uint8_t *const *packets,
                             size_t count, size_t segment_size,
                             uint8_t tclass, bool has_tclass) {
    if (count == 0U || count > UDP_GSO_MAX_SEGMENTS || segment_size == 0U) {
        errno = EINVAL;
        return false;
    }
    if (segment_size > UINT16_MAX) {
        errno = EMSGSIZE;
        return false;
    }
    if (!flow->gso_enabled || count == 1U)
        return send_upstream_views_individual(flow, packets, count, segment_size,
                                              tclass, has_tclass);

    struct vane_error err = {0};
    struct iovec iov[UDP_GSO_MAX_SEGMENTS * 2U];
    struct vane_proxy_header header;
    size_t iov_count = 0U;
    size_t expected = 0U;
    uint16_t wire_segment = (uint16_t)segment_size;
    if (flow->target->proxy_protocol) {
        if (!vane_proxy_v2_encode(&flow->key.client, &flow->key.local,
                                    VANE_PROXY_DGRAM, &header, &err))
            return false;
        size_t wire_size = header.len + segment_size;
        if (wire_size > UINT16_MAX) {
            errno = EMSGSIZE;
            return false;
        }
        wire_segment = (uint16_t)wire_size;
        for (size_t i = 0; i < count; i++) {
            iov[iov_count++] = (struct iovec){.iov_base = header.bytes,
                                              .iov_len = header.len};
            iov[iov_count++] = (struct iovec){.iov_base = (void *)(uintptr_t)packets[i],
                                              .iov_len = segment_size};
            expected += wire_size;
        }
    } else {
        for (size_t i = 0; i < count; i++) {
            iov[iov_count++] = (struct iovec){.iov_base = (void *)(uintptr_t)packets[i],
                                              .iov_len = segment_size};
            expected += segment_size;
        }
    }
    if ((size_t)wire_segment > UDP_GSO_SAFE_BYTES ||
        count > UDP_GSO_SAFE_BYTES / (size_t)wire_segment)
        return send_upstream_views_individual(flow, packets, count, segment_size,
                                              tclass, has_tclass);
    const uint8_t *tc = has_tclass ? &tclass : NULL;
    ssize_t sent = vane_udp_sendmsg(flow->upstream_fd,
                                      flow->target->location.storage.ss_family,
                                      iov, iov_count, NULL, NULL, tc, &wire_segment, &err);
    if (sent == (ssize_t)expected) return true;

    int saved = sent >= 0 ? EIO : errno;
    if (udp_gso_error_disables(saved)) flow->gso_enabled = false;
    if (udp_gso_error_allows_fallback(saved))
        return send_upstream_views_individual(flow, packets, count, segment_size,
                                              tclass, has_tclass);
    errno = saved;
    return false;
}

static bool send_upstream_individual(struct udp_flow *flow,
                                     const uint8_t *data, size_t len,
                                     uint16_t segment_size,
                                     uint8_t tclass, bool has_tclass) {
    if (len == 0U) {
        struct vane_error err = {0};
        return flow->target->proxy_protocol
            ? send_proxy_train(flow, data, 0U, 0U, false, tclass, has_tclass, &err)
            : send_plain_train(flow->upstream_fd, flow->target->location.storage.ss_family,
                               data, 0U, 0U, false,
                               tclass, has_tclass, &err);
    }
    if (segment_size == 0U) {
        errno = EINVAL;
        return false;
    }
    size_t offset = 0;
    while (offset < len) {
        size_t n = VANE_MIN((size_t)segment_size, len - offset);
        struct vane_error err = {0};
        bool ok = flow->target->proxy_protocol
            ? send_proxy_train(flow, data + offset, n, (uint16_t)n, false,
                               tclass, has_tclass, &err)
            : send_plain_train(flow->upstream_fd, flow->target->location.storage.ss_family,
                               data + offset, n,
                               (uint16_t)n, false, tclass, has_tclass, &err);
        if (!ok) return false;
        offset += n;
    }
    return true;
}

bool udp_send_upstream_aggregate(struct udp_flow *flow,
                                 const uint8_t *data, size_t len,
                                 uint16_t segment_size,
                                 uint8_t tclass, bool has_tclass) {
    if (len == 0U)
        return send_upstream_individual(flow, data, 0U, 0U, tclass, has_tclass);
    if (segment_size == 0U) {
        if (len > UINT16_MAX) {
            errno = EMSGSIZE;
            return false;
        }
        segment_size = (uint16_t)len;
    }
    if (segment_size == 0U) {
        errno = EINVAL;
        return false;
    }
    if (!flow->gso_enabled && len > segment_size)
        return send_upstream_individual(flow, data, len, segment_size,
                                        tclass, has_tclass);
    size_t header_len = flow->target->proxy_protocol
        ? (vane_addr_effective_family(&flow->key.client) == AF_INET ? 28U : 52U) : 0U;
    size_t wire_segment = header_len + segment_size;
    size_t max_segments = VANE_MIN((size_t)UDP_GSO_MAX_SEGMENTS,
                                     UDP_GSO_SAFE_BYTES / VANE_MAX(wire_segment, 1U));
    if (max_segments == 0) max_segments = 1;
    size_t offset = 0;
    while (offset < len) {
        size_t remaining = len - offset;
        size_t full = remaining / segment_size;
        size_t segments = VANE_MIN(full, max_segments);
        size_t train_len;
        if (segments == 0) train_len = remaining;
        else {
            train_len = segments * segment_size;
            if (train_len < remaining && segments < max_segments &&
                remaining - train_len < segment_size) train_len = remaining;
        }
        bool use_gso = flow->gso_enabled && train_len > segment_size;
        struct vane_error err = {0};
        bool ok = flow->target->proxy_protocol
            ? send_proxy_train(flow, data + offset, train_len, segment_size,
                               use_gso, tclass, has_tclass, &err)
            : send_plain_train(flow->upstream_fd, flow->target->location.storage.ss_family,
                               data + offset, train_len,
                               segment_size, use_gso, tclass, has_tclass, &err);
        if (!ok && use_gso) {
            int saved = errno;
            if (udp_gso_error_disables(saved)) flow->gso_enabled = false;
            if (udp_gso_error_allows_fallback(saved))
                ok = send_upstream_individual(flow, data + offset, train_len,
                                              segment_size, tclass, has_tclass);
        }
        if (!ok) return false;
        offset += train_len;
    }
    return true;
}

bool udp_forward_upstream(struct udp_worker *worker, size_t id,
                          const uint8_t *data, size_t len,
                          uint8_t tclass, bool has_tclass) {
    struct udp_flow *flow = &worker->flows[id];
    if (udp_send_upstream_aggregate(flow, data, len, (uint16_t)len,
                                    tclass, has_tclass)) {
        return true;
    }

    int saved = errno;
    if (saved == EAGAIN || saved == EWOULDBLOCK || saved == ENOBUFS) {
        LOG_TRACE("UDP worker %zu flow=%zu upstream datagram len=%zu dropped: %s",
                  worker->args->worker_index, id, len, strerror(saved));
        return true;
    }
    (void)udp_flow_handle_io_error(worker, id, "upstream send", saved);
    return false;
}
