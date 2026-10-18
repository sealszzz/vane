#include "udp_internal.h"

#include "vane/log.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

struct udp_probe *udp_probe_get(struct udp_worker *worker,
                                const struct udp_flow *flow) {
    if (flow->probe_id == UINT32_MAX || flow->probe_id >= worker->pending_limit)
        return NULL;
    return &worker->probes[flow->probe_id];
}

static bool probe_acquire(struct udp_worker *worker, struct udp_flow *flow) {
    if (udp_probe_get(worker, flow) != NULL) return true;
    if (worker->free_probe_count == 0U) return false;
    uint32_t id = worker->free_probe_ids[--worker->free_probe_count];
    memset(&worker->probes[id], 0, sizeof(worker->probes[id]));
    flow->probe_id = id;
    return true;
}

static uint8_t *probe_data_acquire(struct udp_worker *worker) {
    if (worker->probe_cache_count != 0U)
        return worker->probe_cache[--worker->probe_cache_count];
    return malloc(UDP_PROBE_INITIAL_BYTES);
}

static void probe_data_release(struct udp_worker *worker, uint8_t *data,
                               size_t capacity) {
    if (data == NULL) return;
    if (capacity == UDP_PROBE_INITIAL_BYTES &&
        worker->probe_cache_count < UDP_PROBE_CACHE_LIMIT) {
        worker->probe_cache[worker->probe_cache_count++] = data;
        return;
    }
    free(data);
}

void udp_probe_destroy(struct udp_worker *worker, struct udp_flow *flow) {
    struct udp_probe *probe = udp_probe_get(worker, flow);
    if (probe == NULL) return;
    vane_quic_probe_state_free(probe->parser);
    probe->parser = NULL;
    if (probe->data != NULL && probe->total_bytes != 0U)
        OPENSSL_cleanse(probe->data, probe->total_bytes);
    probe_data_release(worker, probe->data, probe->capacity);
    memset(probe, 0, sizeof(*probe));
    worker->free_probe_ids[worker->free_probe_count++] = flow->probe_id;
    flow->probe_id = UINT32_MAX;
}

bool udp_probe_append(struct udp_worker *worker, struct udp_flow *flow,
                      const uint8_t *data, size_t len,
                      uint8_t tclass, bool has_tclass) {
    if (!probe_acquire(worker, flow)) return false;
    struct udp_probe *probe = udp_probe_get(worker, flow);
    if (probe == NULL) return false;
    if (probe->count >= worker->args->runtime->udp_probe_max_datagrams ||
        probe->count >= UDP_PROBE_MAX_DATAGRAMS_HARD ||
        probe->total_bytes > worker->args->runtime->udp_probe_max_bytes ||
        len > worker->args->runtime->udp_probe_max_bytes - probe->total_bytes)
        return false;
    size_t required = probe->total_bytes + len;
    if (required > probe->capacity) {
        size_t new_capacity = probe->capacity == 0U
            ? VANE_MIN(UDP_PROBE_INITIAL_BYTES,
                         worker->args->runtime->udp_probe_max_bytes)
            : probe->capacity;
        while (new_capacity < required) {
            size_t next = new_capacity > SIZE_MAX / 2U ? required : new_capacity * 2U;
            if (next > worker->args->runtime->udp_probe_max_bytes)
                next = worker->args->runtime->udp_probe_max_bytes;
            if (next <= new_capacity) {
                new_capacity = required;
                break;
            }
            new_capacity = next;
        }
        uint8_t *new_data;
        if (probe->data == NULL && new_capacity == UDP_PROBE_INITIAL_BYTES) {
            new_data = probe_data_acquire(worker);
        } else {
            new_data = realloc(probe->data, new_capacity);
        }
        if (new_data == NULL) return false;
        probe->data = new_data;
        probe->capacity = new_capacity;
    }
    size_t i = probe->count++;
    probe->offsets[i] = (uint32_t)probe->total_bytes;
    probe->lengths[i] = (uint32_t)len;
    probe->tclasses[i] = tclass;
    probe->has_tclass[i] = has_tclass;
    if (len != 0U) memcpy(probe->data + probe->total_bytes, data, len);
    probe->total_bytes += len;
    flow->probe_activity_ms = vane_monotonic_ms();
    return true;
}

static enum vane_probe_result run_pending_probe(struct udp_worker *worker,
                                                   struct udp_flow *flow,
                                                   struct vane_client_hello *hello,
                                                   struct vane_error *err) {
    struct udp_probe *probe = udp_probe_get(worker, flow);
    if (probe == NULL || probe->count == 0U) {
        vane_error_set(err, "QUIC probe has no datagrams");
        return VANE_PROBE_MALFORMED;
    }
    if (probe->parser == NULL) {
        probe->parser = vane_quic_probe_state_new();
        if (probe->parser == NULL) {
            vane_error_set(err, "out of memory");
            return VANE_PROBE_MALFORMED;
        }
    }
    size_t i = probe->count - 1U;
    return vane_quic_probe_feed(probe->parser,
                                  probe->data + probe->offsets[i],
                                  probe->lengths[i], hello, err);
}

static bool probe_initial_identity(
    const struct udp_probe *probe,
    struct vane_quic_initial_identity *identity) {
    if (probe == NULL || identity == NULL) return false;
    for (size_t i = 0; i < probe->count; i++) {
        const uint8_t *packet = probe->data + probe->offsets[i];
        if (vane_quic_read_initial_identity(packet, probe->lengths[i],
                                              identity))
            return true;
    }
    return false;
}

static bool flush_pending_probe(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    struct udp_probe *probe = udp_probe_get(worker, flow);
    if (probe == NULL) return true;
    for (size_t i = 0; i < probe->count; i++) {
        const uint8_t *packet = probe->data + probe->offsets[i];
        if (!udp_forward_upstream(worker, id, packet, probe->lengths[i],
                                  probe->tclasses[i], probe->has_tclass[i]))
            return false;
    }
    udp_probe_destroy(worker, flow);
    return true;
}

void udp_probe_route(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    bool reprobing = flow->state == UDP_FLOW_REPROBING;
    struct udp_probe *probe = udp_probe_get(worker, flow);
    if (probe == NULL) {
        if (reprobing)
            udp_flow_cancel_reprobe(worker, id, "probe unavailable");
        else
            udp_flow_remove(worker, id);
        return;
    }

    struct vane_client_hello hello;
    struct vane_error err = {0};
    enum vane_probe_result result = run_pending_probe(worker, flow, &hello, &err);
    const struct vane_target_config *target = NULL;
    if (result == VANE_PROBE_MATCHED) {
        target = vane_route_select_tls(worker->args->routes, &hello);
        udp_log_route_decision(worker, id,
                               reprobing ? "quic-reprobe" : "quic",
                               hello.has_sni ? hello.server_name : NULL, target);
    } else if (result == VANE_PROBE_NOT_PROTOCOL) {
        if (reprobing) {
            udp_flow_cancel_reprobe(worker, id, "not QUIC");
            return;
        }
        target = vane_route_select_fallback(worker->args->routes);
        udp_log_route_decision(worker, id, "fallback", NULL, target);
    } else if (result == VANE_PROBE_MALFORMED) {
        char client_buf[96];
        LOG_DEBUG("UDP worker %zu flow=%zu malformed QUIC probe client=%s "
                  "datagrams=%zu bytes=%zu reason=%s",
                  worker->args->worker_index, id,
                  vane_addr_format(&flow->key.client, client_buf,
                                     sizeof(client_buf)),
                  probe->count, probe->total_bytes,
                  err.message[0] != '\0' ? err.message : "unknown");
        if (reprobing)
            udp_flow_cancel_reprobe(worker, id, "malformed QUIC Initial");
        else
            udp_flow_remove(worker, id);
        return;
    } else {
        LOG_TRACE("UDP worker %zu flow=%zu QUIC probe pending datagrams=%zu bytes=%zu",
                  worker->args->worker_index, id, probe->count,
                  probe->total_bytes);
        return;
    }

    struct vane_quic_initial_identity identity;
    bool has_identity = result == VANE_PROBE_MATCHED &&
                        probe_initial_identity(probe, &identity);
    bool activated = reprobing
        ? udp_flow_commit_reprobe(worker, id, target)
        : udp_flow_activate(worker, id, target);
    if (!activated) {
        if (id < worker->flow_capacity &&
            worker->flows[id].state == UDP_FLOW_REPROBING)
            udp_flow_cancel_reprobe(worker, id, "retarget failed");
        return;
    }

    flow = &worker->flows[id];
    if (has_identity)
        udp_flow_set_quic_identity(flow, &identity);
    else if (result != VANE_PROBE_MATCHED)
        udp_flow_set_quic_identity(flow, NULL);
    (void)flush_pending_probe(worker, id);
}
