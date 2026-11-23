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

static bool packet_matches_active_initial(
    const struct udp_flow *flow, const struct vane_quic_initial_identity *identity,
    const uint8_t *data, size_t len) {
    if (udp_flow_quic_identity_matches(flow, identity)) return true;
    const struct vane_quic_initial_identity *original = &flow->quic_identity;
    if (!flow->has_quic_server_dcid ||
        flow->quic_server_version != identity->version ||
        original->source_connection_id_len != identity->source_connection_id_len ||
        memcmp(original->source_connection_id, identity->source_connection_id,
               original->source_connection_id_len) != 0)
        return false;

    /* A rotated DCID can carry an Initial ACK protected with the keys
     * derived from the first client Initial or the observed Retry. */
    const struct vane_datagram_view original_key = {
        original->destination_connection_id, original->destination_connection_id_len
    };
    if (vane_quic_is_initial_control(data, len, &original_key)) return true;
    if (!flow->has_quic_retry_dcid) return false;
    const struct vane_datagram_view retry_key = {
        flow->quic_retry_dcid, flow->quic_retry_dcid_len
    };
    return vane_quic_is_initial_control(data, len, &retry_key);
}

static void append_probe_packet(struct udp_worker *worker, size_t id,
                                const uint8_t *data, size_t len,
                                uint8_t tclass, bool has_tclass) {
    struct udp_flow *flow = &worker->flows[id];
    if (!udp_probe_append(worker, flow, data, len, tclass, has_tclass)) {
        struct udp_probe *probe = udp_probe_get(worker, flow);
        /* Do not destroy an in-progress QUIC Initial handshake when a burst
         * of non-Initial (e.g. 0-RTT) datagrams fills the probe buffer. */
        if (probe != NULL && probe->count > 0U &&
            !vane_quic_looks_like_initial(data, len)) {
            LOG_TRACE("UDP worker %zu flow=%zu dropped excess non-Initial probe packet bytes=%zu",
                      worker->args->worker_index, id, len);
            return;
        }
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
                            size_t id,
                            const uint8_t *data, size_t len,
                            uint8_t tclass, bool has_tclass) {
    bool has_protocol_rules = vane_route_has_protocol_rules(worker->args->routes);
    bool looks_initial = has_protocol_rules &&
                         vane_quic_looks_like_initial(data, len);
    bool looks_zero_rtt = !looks_initial && has_protocol_rules &&
                          vane_quic_looks_like_zero_rtt(data, len);
    struct vane_quic_initial_identity incoming;
    if (looks_initial &&
        !vane_quic_read_initial_identity(data, len, &incoming)) {
        LOG_TRACE("UDP worker %zu rejected invalid QUIC Initial header bytes=%zu",
                  worker->args->worker_index, len);
        return;
    }
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
        bool active_initial = looks_initial &&
                              packet_matches_active_initial(flow, &incoming,
                                                              data, len);
        if (flow->state == UDP_FLOW_REPROBING) {
            bool candidate = looks_initial
                ? vane_quic_initial_identity_equal(&flow->reprobe_identity,
                                                   &incoming)
                : packet_matches_reprobe_candidate(flow, data, len);
            if (candidate && !active_initial)
                append_probe_packet(worker, id, data, len, tclass, has_tclass);
            else if (!looks_initial || active_initial)
                (void)udp_forward_upstream(worker, id, data, len,
                                           tclass, has_tclass);
            return;
        }
        if (flow->state == UDP_FLOW_ACTIVE ||
            flow->state == UDP_FLOW_QUIESCENT) {
            if (looks_initial && !active_initial) {
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

    bool needs_probe = looks_initial || looks_zero_rtt;
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
                                 const struct vane_udp_meta *first_meta,
                                 size_t id) {
    struct mmsghdr *first_msg = &worker->rx_msgs[first];
    size_t segment_size = first_msg->msg_len;
    if (first + 1 == total || segment_size == 0U || first_meta->has_gro)
        return 0U;
    struct udp_flow *flow = &worker->flows[id];
    if (!flow->gso_enabled) return 0U;
    const uint8_t *first_packet =
        worker->rx_storage + (size_t)first * UDP_PACKET_STRIDE;

    size_t header_len = flow->target->proxy_protocol
        ? (vane_addr_effective_family(&flow->key.client) == AF_INET ? 28U : 52U)
        : 0U;
    size_t wire_segment = header_len + segment_size;
    size_t max_count = VANE_MIN((size_t)UDP_GSO_MAX_SEGMENTS,
                                 UDP_GSO_SAFE_BYTES / wire_segment);
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
        if (!vane_udp_parse_meta(&mmsg->msg_hdr,
                                   &worker->args->listener->address,
                                   &meta, NULL) ||
            meta.has_gro || !same_tclass(first_meta, &meta))
            break;
        struct udp_flow_key next_key = {.client = meta.peer,
                                        .local = meta.local};
        if (!udp_flow_key_equal(&flow->key, &next_key)) break;
        /* The identical key still names this flow: this worker owns the
         * table and collecting views does not mutate it. Avoid rehashing. */
        const uint8_t *packet =
            worker->rx_storage + (size_t)j * UDP_PACKET_STRIDE;
        if (active_packet_requires_segment_path(worker, flow, packet,
                                                segment_size))
            break;
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

static size_t process_public_message(struct udp_worker *worker, int index,
                                      int total, const struct vane_udp_meta *meta) {
    const uint8_t *data = worker->rx_storage + (size_t)index * UDP_PACKET_STRIDE;
    size_t len = worker->rx_msgs[index].msg_len;
    struct udp_flow_key key = {.client = meta->peer, .local = meta->local};
    size_t id = udp_flow_lookup_id(worker, &key);
    uint16_t segment = meta->has_gro && meta->gro_segment_size != 0
        ? meta->gro_segment_size : (uint16_t)len;
    if (id != SIZE_MAX &&
        (worker->flows[id].state == UDP_FLOW_ACTIVE ||
         worker->flows[id].state == UDP_FLOW_REPROBING)) {
        struct udp_flow *flow = &worker->flows[id];
        if (!aggregate_requires_segment_path(worker, flow, data, len, segment)) {
            size_t consumed = try_rebatch_public(worker, index, total, meta, id);
            if (consumed != 0U) return consumed;
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
            return 1U;
        }
    }
    size_t offset = 0U;
    do {
        size_t n = VANE_MIN((size_t)segment, len - offset);
        process_segment(worker, &key, id, data + offset, n,
                        meta->tclass, meta->has_tclass);
        offset += n;
        /* Routing a segment can remove or replace the flow. */
        if (offset < len) id = udp_flow_lookup_id(worker, &key);
    } while (offset < len);
    return 1U;
}

void udp_receive_public(struct udp_worker *worker) {
    for (size_t batch = 0U; batch < UDP_PUBLIC_BATCH_QUANTUM; batch++) {
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
            struct vane_error meta_err;
            if (!vane_udp_parse_meta(&mmsg->msg_hdr,
                                       &worker->args->listener->address,
                                       &meta, &meta_err)) {
                LOG_DEBUG("UDP worker %zu ingress metadata parse failed bytes=%u: %s",
                          worker->args->worker_index, mmsg->msg_len,
                          meta_err.message);
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
            i += (int)process_public_message(worker, i, n, &meta);
        }
        /* recvmsg writes only the returned slots. Restore input capacities
         * after processing; flags and msg_len are kernel outputs. */
        for (int i = 0; i < n; i++) {
            worker->rx_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
            worker->rx_msgs[i].msg_hdr.msg_controllen = VANE_UDP_CONTROL_SIZE;
        }
        if ((size_t)n < worker->rx_count) return;
    }
}

static void note_upstream_quic_identity(struct udp_flow *flow,
                                     const uint8_t *data, size_t len,
                                     uint16_t gro_segment_size) {
    if (!flow->has_quic_identity || flow->has_quic_server_dcid) return;
    size_t segment = gro_segment_size != 0U ? gro_segment_size : len;
    size_t offset = 0U;
    while (offset < len) {
        size_t n = VANE_MIN(segment, len - offset);
        struct vane_quic_initial_identity identity;
        if (vane_quic_read_coalesced_initial_identity(data + offset, n, &identity))
            udp_flow_note_quic_initial(flow, &identity);
        else if (vane_quic_looks_like_retry(data + offset, n) &&
                 vane_quic_read_long_header_identity(data + offset, n, &identity))
            udp_flow_note_quic_retry(flow, &identity);
        offset += n;
    }
}

void udp_receive_upstream(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state == UDP_FLOW_QUIESCENT && !udp_flow_resume(worker, id))
        return;
    size_t recoverable_errors = 0U;
    size_t inspected = 0U, received_bytes = 0U;
    while (inspected < UDP_UPSTREAM_RECEIVE_QUANTUM &&
           received_bytes < UDP_UPSTREAM_RECEIVE_BYTES) {
        if (worker->down_count >= worker->down_capacity)
            udp_downstream_flush(worker);
        if (worker->down_count >= worker->down_capacity) return;
        size_t base = worker->down_count;
        size_t avail = worker->down_capacity - base;
        size_t batch_cap = VANE_MIN(worker->rx_count,
            VANE_MIN(avail, UDP_UPSTREAM_RECEIVE_QUANTUM - inspected));
        for (size_t k = 0U; k < batch_cap; k++) {
            struct mmsghdr *mmsg = &worker->up_rx_msgs[k];
            worker->up_rx_iov[k].iov_base =
                worker->down_storage + (base + k) * UDP_PACKET_STRIDE;
            worker->up_rx_iov[k].iov_len = UDP_MAX_PACKET;
            mmsg->msg_len = 0U;
            mmsg->msg_hdr.msg_controllen = VANE_UDP_CONTROL_SIZE;
            mmsg->msg_hdr.msg_flags = 0;
        }
        int got = recvmmsg(flow->upstream_fd, worker->up_rx_msgs,
                           (unsigned int)batch_cap,
                           MSG_DONTWAIT | MSG_TRUNC, NULL);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            int saved = errno;
            if (saved != ENOBUFS &&
                !udp_flow_handle_io_error(worker, id, "upstream receive", saved))
                return;
            if (++recoverable_errors >= UDP_RECEIVE_ERROR_QUANTUM)
                return;
            continue;
        }
        if (got == 0) return;

        uint64_t now = vane_monotonic_ms();
        bool spilled = false;
        for (int k = 0; k < got; k++) {
            inspected++;
            struct mmsghdr *mmsg = &worker->up_rx_msgs[k];
            size_t n = mmsg->msg_len;
            if ((mmsg->msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
                n > UDP_MAX_PACKET) {
                if (!udp_flow_handle_io_error(worker, id, "upstream receive",
                                              EMSGSIZE))
                    return;
                continue;
            }
            uint8_t *buffer = spilled
                ? (worker->rx_storage + (size_t)k * UDP_PACKET_STRIDE)
                : (worker->down_storage + (base + (size_t)k) * UDP_PACKET_STRIDE);
            struct vane_udp_meta meta;
            vane_udp_parse_connected_meta(&mmsg->msg_hdr, &meta);
            received_bytes += n;
            udp_flow_clear_error_history(flow);
            flow->last_activity_ms = now;
            bool first_response = !flow->upstream_confirmed;
            flow->upstream_confirmed = true;
            uint16_t segment = meta.has_gro ? meta.gro_segment_size : 0;
            note_upstream_quic_identity(flow, buffer, n, segment);
            if (first_response) {
                char client_buf[96];
                LOG_DEBUG("UDP worker %zu flow=%zu first upstream response client=%s "
                          "bytes=%zu gro=%s segment=%u",
                          worker->args->worker_index, id,
                          vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
                          n, meta.has_gro ? "on" : "off", (unsigned)segment);
            } else {
                LOG_TRACE("UDP worker %zu flow=%zu upstream response bytes=%zu gro=%s segment=%u",
                          worker->args->worker_index, id, n,
                          meta.has_gro ? "on" : "off", (unsigned)segment);
            }
            /* Most receives fit one downstream slot and stay zero-copy.
             * A GRO train requiring multiple output slots must be staged
             * before queueing: its source can otherwise be overwritten when
             * the queue flushes/reuses down_storage, even with no later
             * recvmmsg result. Also stage later results before a split train
             * overwrites their pre-filled output slots. */
            if (!spilled && segment != 0U && n > (size_t)segment &&
                n > udp_gso_segments_per_train(segment) * (size_t)segment) {
                for (int j = k; j < got; j++) {
                    size_t jlen = worker->up_rx_msgs[j].msg_len;
                    if (jlen != 0U && jlen <= UDP_MAX_PACKET) {
                        memcpy(worker->rx_storage + (size_t)j * UDP_PACKET_STRIDE,
                               worker->down_storage + (base + (size_t)j) * UDP_PACKET_STRIDE,
                               jlen);
                    }
                }
                spilled = true;
                buffer = worker->rx_storage + (size_t)k * UDP_PACKET_STRIDE;
            }
            udp_downstream_queue(worker, flow, buffer, n, segment,
                                 meta.tclass, meta.has_tclass);
            if (worker->down_count == worker->down_capacity)
                udp_downstream_flush(worker);
        }
        if ((size_t)got < batch_cap) return;
    }
}
