#include "udp_internal.h"

#include "vane/log.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>

static bool packet_matches_reprobe_candidate(
    const struct udp_flow *flow, const uint8_t *data, size_t len) {
    struct vane_quic_initial_identity identity;
    return flow->state == UDP_FLOW_REPROBING &&
           vane_quic_read_long_header_identity(data, len, &identity) &&
           vane_quic_initial_identity_equal(&flow->reprobe_identity,
                                               &identity);
}

static void append_probe_packet(struct udp_worker *worker, size_t id,
                                const uint8_t *data, size_t len,
                                uint8_t tclass, bool has_tclass) {
    struct udp_flow *flow = &worker->flows[id];
    if (!udp_probe_append(worker, flow, data, len, tclass, has_tclass)) {
        struct udp_probe *probe = udp_probe_get(worker, flow);
        LOG_DEBUG("UDP worker %zu flow=%zu QUIC probe overflow datagrams=%zu "
                  "bytes=%zu incoming=%zu state=%s",
                  worker->args->worker_index, id,
                  probe != NULL ? probe->count : 0U,
                  probe != NULL ? probe->total_bytes : 0U, len,
                  flow->state == UDP_FLOW_REPROBING ? "reprobing" : "pending");
        if (flow->state == UDP_FLOW_REPROBING)
            udp_flow_cancel_reprobe(worker, id, "probe capacity exceeded");
        else
            udp_flow_remove(worker, id);
        return;
    }
    udp_probe_route(worker, id);
}

static bool begin_reprobe_for_packet(
    struct udp_worker *worker, size_t id,
    const struct vane_quic_initial_identity *identity,
    const uint8_t *data, size_t len, uint8_t tclass, bool has_tclass) {
    struct udp_flow *flow = &worker->flows[id];
    if (!udp_flow_begin_reprobe(worker, id, identity)) {
        char client_buf[96];
        LOG_DEBUG("UDP worker %zu flow=%zu QUIC reprobe deferred client=%s "
                  "pending=%zu/%zu",
                  worker->args->worker_index, id,
                  vane_addr_format(&flow->key.client, client_buf,
                                     sizeof(client_buf)),
                  worker->pending_count, worker->pending_limit);
        return false;
    }
    LOG_DEBUG("UDP worker %zu flow=%zu new QUIC connection candidate "
              "scid_len=%zu",
              worker->args->worker_index, id,
              identity->source_connection_id_len);
    append_probe_packet(worker, id, data, len, tclass, has_tclass);
    return true;
}

static void process_segment(struct udp_worker *worker,
                            const struct udp_flow_key *key,
                            const uint8_t *data, size_t len,
                            uint8_t tclass, bool has_tclass) {
    bool has_protocol_rules = vane_route_has_protocol_rules(worker->args->routes);
    bool looks_initial = has_protocol_rules &&
                         vane_quic_looks_like_initial(data, len);
    struct vane_quic_initial_identity incoming;
    if (looks_initial &&
        !vane_quic_read_initial_identity(data, len, &incoming)) {
        LOG_TRACE("UDP worker %zu rejected invalid QUIC Initial header bytes=%zu",
                  worker->args->worker_index, len);
        return;
    }
    size_t id = udp_flow_lookup_id(worker, key);
    uint64_t now = vane_monotonic_ms();
    if (id != SIZE_MAX) {
        struct udp_flow *flow = &worker->flows[id];
        if (flow->state != UDP_FLOW_PENDING && looks_initial &&
            udp_flow_quic_identity_retired(flow, &incoming, now)) {
            LOG_TRACE("UDP worker %zu flow=%zu dropped retired QUIC Initial",
                      worker->args->worker_index, id);
            return;
        }
        flow->last_activity_ms = now;
        if (flow->state == UDP_FLOW_PENDING) {
            append_probe_packet(worker, id, data, len, tclass, has_tclass);
            return;
        }
        if (flow->state == UDP_FLOW_REPROBING) {
            if (packet_matches_reprobe_candidate(flow, data, len))
                append_probe_packet(worker, id, data, len, tclass, has_tclass);
            else if (!looks_initial ||
                     udp_flow_quic_identity_matches(flow, &incoming))
                (void)udp_forward_upstream(worker, id, data, len,
                                           tclass, has_tclass);
            return;
        }
        if (flow->state == UDP_FLOW_ACTIVE ||
            flow->state == UDP_FLOW_QUIESCENT) {
            if (looks_initial &&
                !udp_flow_quic_identity_matches(flow, &incoming)) {
                (void)begin_reprobe_for_packet(worker, id, &incoming,
                                               data, len, tclass, has_tclass);
                return;
            }
            if (flow->state == UDP_FLOW_QUIESCENT &&
                !udp_flow_resume(worker, id))
                return;
            (void)udp_forward_upstream(worker, id, data, len,
                                       tclass, has_tclass);
            return;
        }
    }

    bool needs_probe = looks_initial;
    size_t new_id = 0;
    struct udp_flow *flow = udp_flow_insert(worker, key, needs_probe, &new_id);
    if (flow == NULL) {
        char client_buf[96];
        LOG_DEBUG("UDP worker %zu new flow rejected client=%s active=%zu/%zu "
                  "pending=%zu/%zu",
                  worker->args->worker_index,
                  vane_addr_format(&key->client, client_buf,
                                     sizeof(client_buf)),
                  worker->flow_count, worker->flow_limit,
                  worker->pending_count, worker->pending_limit);
        return;
    }
    if (!needs_probe) {
        const struct vane_target_config *target =
            vane_route_select_fallback(worker->args->routes);
        udp_log_route_decision(worker, new_id, "fallback", NULL, target);
        if (udp_flow_activate(worker, new_id, target))
            (void)udp_forward_upstream(worker, new_id, data, len,
                                       tclass, has_tclass);
        return;
    }
    append_probe_packet(worker, new_id, data, len, tclass, has_tclass);
}

static bool same_tclass(const struct vane_udp_meta *a,
                        const struct vane_udp_meta *b) {
    return a->has_tclass == b->has_tclass &&
           (!a->has_tclass || a->tclass == b->tclass);
}

static bool active_packet_requires_segment_path(
    const struct udp_worker *worker, const struct udp_flow *flow,
    const uint8_t *data, size_t len) {
    /* Validate every recognized Initial before allowing an aggregate fast
     * path, including malformed and undersized headers on an existing flow. */
    if (vane_route_has_protocol_rules(worker->args->routes) &&
        vane_quic_looks_like_initial(data, len))
        return true;
    return flow->state == UDP_FLOW_REPROBING &&
           packet_matches_reprobe_candidate(flow, data, len);
}

static size_t try_rebatch_public(struct udp_worker *worker, int first, int total,
                                 const struct vane_udp_meta *first_meta) {
    struct mmsghdr *first_msg = &worker->rx_msgs[first];
    size_t segment_size = first_msg->msg_len;
    if (segment_size == 0U || first_meta->has_gro) return 0U;
    struct udp_flow_key key = {.client = first_meta->peer,
                               .local = first_meta->local};
    size_t id = udp_flow_lookup_id(worker, &key);
    if (id == SIZE_MAX ||
        (worker->flows[id].state != UDP_FLOW_ACTIVE &&
         worker->flows[id].state != UDP_FLOW_REPROBING))
        return 0U;
    struct udp_flow *flow = &worker->flows[id];
    const uint8_t *first_packet =
        worker->rx_storage + (size_t)first * UDP_MAX_PACKET;
    if (active_packet_requires_segment_path(worker, flow, first_packet,
                                            segment_size))
        return 0U;

    size_t header_len = flow->target->proxy_protocol
        ? (vane_addr_effective_family(&flow->key.client) == AF_INET ? 28U : 52U)
        : 0U;
    size_t wire_segment = header_len + segment_size;
    size_t max_count = VANE_MIN((size_t)UDP_GSO_MAX_SEGMENTS,
                                  UDP_GSO_SAFE_BYTES /
                                      VANE_MAX(wire_segment, 1U));
    if (max_count < 2U) return 0U;

    const uint8_t *packets[UDP_GSO_MAX_SEGMENTS];
    packets[0] = first_packet;
    size_t count = 1U;
    for (int j = first + 1; j < total && count < max_count; j++) {
        struct mmsghdr *mmsg = &worker->rx_msgs[j];
        if ((mmsg->msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
            mmsg->msg_len != segment_size)
            break;
        struct vane_udp_meta meta;
        struct vane_error meta_err = {0};
        if (!vane_udp_parse_meta(&mmsg->msg_hdr,
                                   &worker->args->listener->address,
                                   &meta, &meta_err) ||
            meta.has_gro || !same_tclass(first_meta, &meta))
            break;
        struct udp_flow_key next_key = {.client = meta.peer,
                                        .local = meta.local};
        if (!udp_flow_key_equal(&key, &next_key)) break;
        size_t next_id = udp_flow_lookup_id(worker, &next_key);
        if (next_id != id ||
            (worker->flows[next_id].state != UDP_FLOW_ACTIVE &&
             worker->flows[next_id].state != UDP_FLOW_REPROBING))
            break;
        const uint8_t *packet =
            worker->rx_storage + (size_t)j * UDP_MAX_PACKET;
        if (active_packet_requires_segment_path(worker, flow, packet,
                                                segment_size))
            return 0U;
        packets[count++] = packet;
    }
    if (count < 2U) return 0U;
    flow->last_activity_ms = vane_monotonic_ms();
    if (!udp_send_upstream_views(flow, packets, count, segment_size,
                                 first_meta->tclass,
                                 first_meta->has_tclass)) {
        int saved = errno;
        if (saved != EAGAIN && saved != EWOULDBLOCK && saved != ENOBUFS) {
            (void)udp_flow_handle_io_error(worker, id, "upstream rebatch",
                                           saved);
        } else {
            LOG_TRACE("UDP worker %zu flow=%zu rebatch count=%zu dropped: %s",
                      worker->args->worker_index, id, count, strerror(saved));
        }
    } else {
        LOG_TRACE("UDP worker %zu flow=%zu rebatch count=%zu segment=%zu",
                  worker->args->worker_index, id, count, segment_size);
    }
    return count;
}

static bool aggregate_requires_segment_path(
    const struct udp_worker *worker, const struct udp_flow *flow,
    const uint8_t *data, size_t len, size_t segment) {
    size_t offset = 0U;
    while (offset < len) {
        size_t n = VANE_MIN(segment, len - offset);
        if (active_packet_requires_segment_path(worker, flow,
                                                data + offset, n))
            return true;
        offset += n;
    }
    return false;
}

static void process_public_aggregate(struct udp_worker *worker,
                                     const struct vane_udp_meta *meta,
                                     const uint8_t *data, size_t len) {
    struct udp_flow_key key = {.client = meta->peer, .local = meta->local};
    if (len == 0U) {
        process_segment(worker, &key, data, 0U,
                        meta->tclass, meta->has_tclass);
        return;
    }
    size_t id = udp_flow_lookup_id(worker, &key);
    uint16_t segment = meta->has_gro && meta->gro_segment_size != 0
        ? meta->gro_segment_size : (uint16_t)len;
    if (id != SIZE_MAX &&
        (worker->flows[id].state == UDP_FLOW_ACTIVE ||
         worker->flows[id].state == UDP_FLOW_REPROBING)) {
        struct udp_flow *flow = &worker->flows[id];
        if (!aggregate_requires_segment_path(worker, flow, data, len, segment)) {
            flow->last_activity_ms = vane_monotonic_ms();
            if (!udp_send_upstream_aggregate(flow, data, len, segment,
                                             meta->tclass,
                                             meta->has_tclass)) {
                int saved = errno;
                if (saved != EAGAIN && saved != EWOULDBLOCK &&
                    saved != ENOBUFS) {
                    (void)udp_flow_handle_io_error(worker, id,
                                                   "upstream aggregate",
                                                   saved);
                } else {
                    LOG_TRACE("UDP worker %zu flow=%zu upstream aggregate "
                              "bytes=%zu dropped: %s",
                              worker->args->worker_index, id, len,
                              strerror(saved));
                }
            }
            return;
        }
    }
    size_t offset = 0U;
    while (offset < len) {
        size_t n = VANE_MIN((size_t)segment, len - offset);
        process_segment(worker, &key, data + offset, n,
                        meta->tclass, meta->has_tclass);
        offset += n;
    }
}

static void reset_rx_messages(struct udp_worker *worker) {
    for (size_t i = 0; i < worker->rx_count; i++) {
        struct mmsghdr *mmsg = &worker->rx_msgs[i];
        struct iovec *iov = &worker->rx_iov[i];
        struct sockaddr_storage *peer = &worker->rx_peers[i];
        unsigned char *control = worker->rx_controls + i * VANE_UDP_CONTROL_SIZE;
        memset(mmsg, 0, sizeof(*mmsg));
        memset(peer, 0, sizeof(*peer));
        memset(control, 0, VANE_UDP_CONTROL_SIZE);
        iov->iov_base = worker->rx_storage + i * UDP_MAX_PACKET;
        iov->iov_len = UDP_MAX_PACKET;
        mmsg->msg_hdr.msg_name = peer;
        mmsg->msg_hdr.msg_namelen = sizeof(*peer);
        mmsg->msg_hdr.msg_iov = iov;
        mmsg->msg_hdr.msg_iovlen = 1;
        mmsg->msg_hdr.msg_control = control;
        mmsg->msg_hdr.msg_controllen = VANE_UDP_CONTROL_SIZE;
    }
}

void udp_receive_public(struct udp_worker *worker) {
    for (size_t batch = 0U; batch < UDP_PUBLIC_BATCH_QUANTUM; batch++) {
        reset_rx_messages(worker);
        int n = recvmmsg(worker->public_fd, worker->rx_msgs,
                         (unsigned int)worker->rx_count, MSG_DONTWAIT, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
                LOG_WARN("UDP worker %zu recvmmsg failed: %s",
                         worker->args->worker_index, strerror(errno));
            return;
        }
        if (n == 0) return;
        for (int i = 0; i < n;) {
            struct mmsghdr *mmsg = &worker->rx_msgs[i];
            if ((mmsg->msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
                mmsg->msg_len > UDP_MAX_PACKET) {
                LOG_DEBUG("UDP worker %zu ingress truncated flags=0x%x bytes=%u",
                          worker->args->worker_index,
                          mmsg->msg_hdr.msg_flags, mmsg->msg_len);
                i++;
                continue;
            }
            struct vane_udp_meta meta;
            struct vane_error meta_err = {0};
            if (!vane_udp_parse_meta(&mmsg->msg_hdr,
                                       &worker->args->listener->address,
                                       &meta, &meta_err)) {
                LOG_DEBUG("UDP worker %zu ingress metadata parse failed bytes=%u: %s",
                          worker->args->worker_index, mmsg->msg_len,
                          meta_err.message[0] != '\0' ? meta_err.message : strerror(errno));
                i++;
                continue;
            }
            char peer_buf[96];
            char local_buf[96];
            LOG_TRACE("UDP worker %zu ingress peer=%s local=%s bytes=%u gro=%s segment=%u",
                      worker->args->worker_index,
                      vane_addr_format(&meta.peer, peer_buf, sizeof(peer_buf)),
                      vane_addr_format(&meta.local, local_buf, sizeof(local_buf)),
                      mmsg->msg_len, meta.has_gro ? "on" : "off",
                      (unsigned)meta.gro_segment_size);
            size_t consumed = try_rebatch_public(worker, i, n, &meta);
            if (consumed != 0U) {
                i += (int)consumed;
                continue;
            }
            const uint8_t *data = worker->rx_storage + (size_t)i * UDP_MAX_PACKET;
            process_public_aggregate(worker, &meta, data, mmsg->msg_len);
            i++;
        }
        if ((size_t)n < worker->rx_count) return;
    }
}

static void note_upstream_quic_retry(struct udp_flow *flow,
                                     const uint8_t *data, size_t len,
                                     uint16_t gro_segment_size) {
    size_t segment = gro_segment_size != 0U ? gro_segment_size : len;
    size_t offset = 0U;
    while (offset < len) {
        size_t n = VANE_MIN(segment, len - offset);
        struct vane_quic_initial_identity identity;
        if (vane_quic_looks_like_retry(data + offset, n) &&
            vane_quic_read_long_header_identity(data + offset, n,
                                                  &identity))
            udp_flow_note_quic_retry(flow, &identity);
        offset += n;
    }
}

static void rearm_upstream(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLET,
        .data.u64 = udp_event_token(UDP_EVENT_UPSTREAM,
            (uint32_t)id, flow->generation),
    };
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD,
                  flow->upstream_fd, &event) != 0) {
        int saved = errno;
        LOG_WARN("UDP worker %zu flow=%zu upstream rearm failed: %s",
                 worker->args->worker_index, id, strerror(saved));
        udp_flow_remove(worker, id);
    }
}

void udp_receive_upstream(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state == UDP_FLOW_QUIESCENT && !udp_flow_resume(worker, id))
        return;
    size_t recoverable_errors = 0U;
    size_t received = 0U, received_bytes = 0U;
    while (received < UDP_UPSTREAM_RECEIVE_QUANTUM &&
           received_bytes < UDP_UPSTREAM_RECEIVE_BYTES) {
        uint8_t *buffer = worker->upstream_rx_storage;
        struct vane_udp_meta meta;
        struct vane_error err = {0};
        ssize_t n = vane_udp_recvmsg(flow->upstream_fd, buffer,
                                       UDP_MAX_PACKET,
                                       &flow->upstream_local, &meta, &err);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            int saved = errno;
            if (saved != ENOBUFS &&
                !udp_flow_handle_io_error(worker, id, "upstream receive", saved))
                return;
            /* A consumed asynchronous error can coexist with queued payload.
             * Preserve ET readiness until EAGAIN; rearm if errors exhaust the
             * bounded retry budget so no queued response needs a new packet. */
            if (++recoverable_errors >= UDP_RECEIVE_ERROR_QUANTUM) {
                rearm_upstream(worker, id);
                return;
            }
            continue;
        }
        received++;
        received_bytes += (size_t)n;
        udp_flow_clear_error_history(flow);
        flow->last_activity_ms = vane_monotonic_ms();
        bool first_response = !flow->upstream_confirmed;
        flow->upstream_confirmed = true;
        uint16_t segment = meta.has_gro ? meta.gro_segment_size : 0;
        note_upstream_quic_retry(flow, buffer, (size_t)n, segment);
        if (first_response) {
            char client_buf[96];
            LOG_DEBUG("UDP worker %zu flow=%zu first upstream response client=%s "
                      "bytes=%zd gro=%s segment=%u",
                      worker->args->worker_index, id,
                      vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
                      n, meta.has_gro ? "on" : "off", (unsigned)segment);
        } else {
            LOG_TRACE("UDP worker %zu flow=%zu upstream response bytes=%zd gro=%s segment=%u",
                      worker->args->worker_index, id, n,
                      meta.has_gro ? "on" : "off", (unsigned)segment);
        }
        udp_downstream_queue(worker, flow, buffer, (size_t)n, segment,
                             meta.tclass, meta.has_tclass);
        if (worker->down_count == worker->down_capacity) udp_downstream_flush(worker);
    }
    /* A busy upstream must yield even when it never reaches EAGAIN. MOD
     * schedules another turn for already queued payload, without requiring
     * any later packet to create an edge. Flush before servicing other flows. */
    udp_downstream_flush(worker);
    rearm_upstream(worker, id);
}
