#include "udp_internal.h"

#include "vane/log.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *target_format(const struct vane_target_config *target,
                                 char *buf, size_t buf_len) {
    if (target == NULL) {
        (void)snprintf(buf, buf_len, "<no-route>");
        return buf;
    }
    if (target->location_kind == VANE_LOCATION_DROP) {
        (void)snprintf(buf, buf_len, "drop");
        return buf;
    }
    return vane_addr_format(&target->location, buf, buf_len);
}

void udp_log_route_decision(const struct udp_worker *worker, size_t id,
                            const char *classification, const char *sni,
                            const struct vane_target_config *target) {
    const struct udp_flow *flow = &worker->flows[id];
    char client_buf[96];
    char local_buf[96];
    char target_buf[96];
    LOG_DEBUG("UDP worker %zu flow=%zu class=%s client=%s local=%s sni=%s "
              "target=%s proxy_protocol=%s",
              worker->args->worker_index, id, classification,
              vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
              vane_addr_format(&flow->key.local, local_buf, sizeof(local_buf)),
              sni != NULL ? sni : "<none>",
              target_format(target, target_buf, sizeof(target_buf)),
              target != NULL && target->proxy_protocol ? "on" : "off");
}

static uint64_t key_hash(const struct udp_flow_key *key, uint64_t seed) {
    uint64_t a = vane_addr_hash(&key->client, seed);
    return vane_addr_hash(&key->local, a ^ UINT64_C(0x9e3779b97f4a7c15));
}

bool udp_flow_key_equal(const struct udp_flow_key *a,
                        const struct udp_flow_key *b) {
    return vane_addr_equal(&a->client, &b->client) &&
           vane_addr_equal(&a->local, &b->local);
}

size_t udp_next_power_of_two(size_t value) {
    size_t n = 1;
    while (n < value && n <= SIZE_MAX / 2U) n <<= 1;
    return n;
}

static size_t flow_index_find(const struct udp_worker *worker,
                              const struct udp_flow_key *key, bool *found) {
    size_t mask = worker->table_capacity - 1U;
    size_t slot = (size_t)key_hash(key, worker->hash_seed) & mask;
    for (size_t probe = 0; probe < worker->table_capacity; probe++) {
        uint32_t encoded = worker->flow_index[slot].flow_id_plus_one;
        if (encoded == 0U) {
            *found = false;
            return slot;
        }
        size_t id = (size_t)(encoded - 1U);
        if (id < worker->flow_capacity &&
            udp_flow_key_equal(&worker->flows[id].key, key)) {
            *found = true;
            return slot;
        }
        slot = (slot + 1U) & mask;
    }
    *found = false;
    return SIZE_MAX;
}

size_t udp_flow_lookup_id(const struct udp_worker *worker,
                          const struct udp_flow_key *key) {
    bool found = false;
    size_t slot = flow_index_find(worker, key, &found);
    if (!found || slot == SIZE_MAX) return SIZE_MAX;
    return (size_t)(worker->flow_index[slot].flow_id_plus_one - 1U);
}

static bool flow_index_insert(struct udp_worker *worker, size_t id) {
    bool found = false;
    size_t slot = flow_index_find(worker, &worker->flows[id].key, &found);
    if (found || slot == SIZE_MAX || id >= UINT32_MAX) return false;
    worker->flow_index[slot].flow_id_plus_one = (uint32_t)id + 1U;
    worker->flows[id].hash_slot = slot;
    return true;
}

static void flow_index_remove(struct udp_worker *worker, size_t id) {
    size_t mask = worker->table_capacity - 1U;
    size_t hole = worker->flows[id].hash_slot;
    size_t scan = (hole + 1U) & mask;
    while (worker->flow_index[scan].flow_id_plus_one != 0U) {
        size_t moved_id = (size_t)(worker->flow_index[scan].flow_id_plus_one - 1U);
        size_t home = (size_t)key_hash(&worker->flows[moved_id].key,
                                       worker->hash_seed) & mask;
        size_t distance_to_scan = (scan - home) & mask;
        size_t distance_hole_to_scan = (scan - hole) & mask;
        if (distance_to_scan >= distance_hole_to_scan) {
            worker->flow_index[hole] = worker->flow_index[scan];
            worker->flows[moved_id].hash_slot = hole;
            hole = scan;
        }
        scan = (scan + 1U) & mask;
    }
    worker->flow_index[hole].flow_id_plus_one = 0U;
}

void udp_flow_remove(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_PENDING && flow->state != UDP_FLOW_ACTIVE &&
        flow->state != UDP_FLOW_REPROBING &&
        flow->state != UDP_FLOW_QUIESCENT)
        return;
    flow_index_remove(worker, id);
    if (flow->probe_accounted && worker->pending_count != 0U)
        worker->pending_count--;
    if (flow->upstream_fd >= 0) {
        (void)epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, flow->upstream_fd, NULL);
        close(flow->upstream_fd);
    }
    udp_probe_destroy(worker, flow);
    uint32_t generation = flow->generation + 1U;
    if (generation == 0U) generation = 1U;
    memset(flow, 0, sizeof(*flow));
    flow->state = UDP_FLOW_EMPTY;
    flow->upstream_fd = -1;
    flow->generation = generation;
    flow->probe_id = UINT32_MAX;
    worker->free_flow_ids[worker->free_flow_count++] = (uint32_t)id;
    if (worker->flow_count != 0U) worker->flow_count--;
}

static void udp_flow_quiesce(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_ACTIVE || !flow->upstream_confirmed ||
        flow->target == NULL || flow->upstream_fd < 0) {
        udp_flow_remove(worker, id);
        return;
    }

    flow->state = UDP_FLOW_QUIESCENT;

    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_DEBUG("UDP worker %zu flow=%zu state=active->quiescent client=%s "
              "target=%s source=%s",
              worker->args->worker_index, id,
              vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
              target_format(flow->target, target_buf, sizeof(target_buf)),
              vane_addr_format(&flow->upstream_local, source_buf, sizeof(source_buf)));
}

bool udp_flow_resume(struct udp_worker *worker, size_t id) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state == UDP_FLOW_ACTIVE ||
        flow->state == UDP_FLOW_REPROBING)
        return true;
    if (flow->state != UDP_FLOW_QUIESCENT || flow->upstream_fd < 0 ||
        flow->target == NULL)
        return false;

    flow->state = UDP_FLOW_ACTIVE;
    flow->last_activity_ms = vane_monotonic_ms();

    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_DEBUG("UDP worker %zu flow=%zu state=quiescent->active client=%s "
              "target=%s source=%s",
              worker->args->worker_index, id,
              vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
              target_format(flow->target, target_buf, sizeof(target_buf)),
              vane_addr_format(&flow->upstream_local, source_buf, sizeof(source_buf)));
    return true;
}

static size_t flow_watermark(size_t capacity, unsigned int percent) {
    return capacity * (size_t)percent / 100U;
}

static bool flow_reclaimable(const struct udp_worker *worker,
                             const struct udp_flow *flow, uint64_t now) {
    uint64_t idle = now - flow->last_activity_ms;
    if (flow->state == UDP_FLOW_PENDING)
        return idle >= worker->args->runtime->udp_probe_timeout_ms;
    if (flow->state == UDP_FLOW_ACTIVE && !flow->upstream_confirmed)
        return idle >= worker->args->runtime->udp_unconfirmed_idle_timeout_ms;
    if ((flow->state == UDP_FLOW_ACTIVE ||
         flow->state == UDP_FLOW_QUIESCENT) &&
        flow->upstream_confirmed)
        return idle >= worker->args->runtime->udp_flow_quiescent_after_ms;
    return false;
}

static int reclaim_candidate_compare(const void *left, const void *right) {
    const struct udp_reclaim_candidate *a = left;
    const struct udp_reclaim_candidate *b = right;
    if (a->last_activity_ms < b->last_activity_ms) return -1;
    if (a->last_activity_ms > b->last_activity_ms) return 1;
    if (a->flow_id < b->flow_id) return -1;
    if (a->flow_id > b->flow_id) return 1;
    return 0;
}

static size_t reclaim_oldest_flows(struct udp_worker *worker, uint64_t now,
                                   size_t target_count) {
    size_t candidate_count = 0U;
    for (size_t i = 0; i < worker->flow_capacity; i++) {
        const struct udp_flow *flow = &worker->flows[i];
        if (!flow_reclaimable(worker, flow, now)) continue;
        worker->reclaim_candidates[candidate_count++] =
            (struct udp_reclaim_candidate){
                .last_activity_ms = flow->last_activity_ms,
                .flow_id = (uint32_t)i,
            };
    }
    qsort(worker->reclaim_candidates, candidate_count,
          sizeof(*worker->reclaim_candidates), reclaim_candidate_compare);

    size_t removed = 0U;
    for (size_t i = 0; i < candidate_count &&
                       worker->flow_count > target_count; i++) {
        size_t id = worker->reclaim_candidates[i].flow_id;
        if (id >= worker->flow_capacity ||
            worker->flows[id].state == UDP_FLOW_EMPTY)
            continue;
        udp_flow_remove(worker, id);
        removed++;
    }
    return removed;
}

static void udp_flow_manage_capacity(struct udp_worker *worker, uint64_t now) {
    size_t base_low = flow_watermark(worker->flow_base_limit,
                                     UDP_FLOW_LOW_WATER_PERCENT);
    if (worker->flow_limit == worker->flow_capacity &&
        worker->flow_count <= base_low) {
        worker->flow_limit = worker->flow_base_limit;
        LOG_INFO("UDP worker %zu flow capacity burst->base used=%zu limit=%zu",
                 worker->args->worker_index, worker->flow_count,
                 worker->flow_limit);
    }

    size_t high = flow_watermark(worker->flow_limit,
                                 UDP_FLOW_HIGH_WATER_PERCENT);
    if (worker->flow_count < high) return;
    if (worker->flow_limit == worker->flow_capacity &&
        now < worker->next_capacity_scan_ms)
        return;
    worker->next_capacity_scan_ms = now + 1000U;

    size_t low = flow_watermark(worker->flow_limit,
                                UDP_FLOW_LOW_WATER_PERCENT);
    size_t before = worker->flow_count;
    size_t removed = reclaim_oldest_flows(worker, now, low);
    if (removed != 0U) {
        LOG_DEBUG("UDP worker %zu flow pressure reclaimed=%zu used=%zu/%zu",
                  worker->args->worker_index, removed, worker->flow_count,
                  worker->flow_limit);
    }

    if (worker->flow_limit == worker->flow_base_limit &&
        worker->flow_count > low) {
        worker->flow_limit = worker->flow_capacity;
        LOG_INFO("UDP worker %zu flow capacity base->burst used=%zu limit=%zu "
                 "reclaimed=%zu",
                 worker->args->worker_index, worker->flow_count,
                 worker->flow_limit, before - worker->flow_count);
    }
}

struct udp_flow *udp_flow_insert(struct udp_worker *worker,
                                 const struct udp_flow_key *key,
                                 bool account_probe, size_t *id_out) {
    uint64_t now = vane_monotonic_ms();
    udp_flow_manage_capacity(worker, now);
    if (worker->flow_count >= worker->flow_limit ||
        worker->free_flow_count == 0U)
        return NULL;
    if (account_probe && worker->pending_count >= worker->pending_limit)
        return NULL;
    size_t id = (size_t)worker->free_flow_ids[--worker->free_flow_count];
    struct udp_flow *flow = &worker->flows[id];
    uint32_t generation = flow->generation == 0U ? 1U : flow->generation;
    memset(flow, 0, sizeof(*flow));
    flow->state = UDP_FLOW_PENDING;
    flow->generation = generation;
    flow->key = *key;
    flow->upstream_fd = -1;
    flow->gso_enabled = true;
    flow->probe_accounted = account_probe;
    flow->probe_id = UINT32_MAX;
    flow->last_activity_ms = now;
    if (!flow_index_insert(worker, id)) {
        memset(flow, 0, sizeof(*flow));
        flow->state = UDP_FLOW_EMPTY;
        flow->upstream_fd = -1;
        flow->generation = generation;
        flow->probe_id = UINT32_MAX;
        worker->free_flow_ids[worker->free_flow_count++] = (uint32_t)id;
        return NULL;
    }
    worker->flow_count++;
    if (account_probe) worker->pending_count++;
    *id_out = id;
    return flow;
}

static bool configure_upstream_socket(int fd,
                                      const struct vane_runtime_config *rt) {
    int recvbuf = (int)rt->upstream_recv_buffer_bytes;
    int sendbuf = (int)rt->upstream_send_buffer_bytes;
    int saved = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf)) != 0)
        saved = errno;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf)) != 0 &&
        saved == 0)
        saved = errno;
    if (saved == 0) return true;
    errno = saved;
    return false;
}

struct udp_upstream_socket {
    int fd;
    int gro;
    struct vane_addr local;
};

static bool open_upstream_socket(struct udp_worker *worker, size_t id,
                                 const struct vane_target_config *target,
                                 uint32_t generation,
                                 struct udp_upstream_socket *out) {
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    int family = target->location.storage.ss_family;
    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    IPPROTO_UDP);
    if (fd < 0) {
        char target_buf[96];
        LOG_WARN("UDP worker %zu flow=%zu upstream socket target=%s failed: %s",
                 worker->args->worker_index, id,
                 target_format(target, target_buf, sizeof(target_buf)),
                 strerror(errno));
        return false;
    }
    if (!configure_upstream_socket(fd, worker->args->runtime)) {
        char target_buf[96];
        LOG_WARN("UDP worker %zu flow=%zu upstream socket options target=%s failed: %s",
                 worker->args->worker_index, id,
                 target_format(target, target_buf, sizeof(target_buf)),
                 strerror(errno));
        close(fd);
        return false;
    }
    struct vane_error err = {0};
    int gro = vane_udp_enable_metadata(fd, family, true, &err);
    if (gro < 0) {
        char target_buf[96];
        LOG_WARN("UDP worker %zu flow=%zu upstream metadata target=%s failed: %s",
                 worker->args->worker_index, id,
                 target_format(target, target_buf, sizeof(target_buf)),
                 err.message);
        close(fd);
        return false;
    }
    int connect_rc;
    do {
        connect_rc = connect(fd,
                             (const struct sockaddr *)&target->location.storage,
                             target->location.len);
    } while (connect_rc != 0 && errno == EINTR);
    if (connect_rc != 0) {
        char target_buf[96];
        LOG_WARN("UDP worker %zu flow=%zu connect target=%s failed: %s",
                 worker->args->worker_index, id,
                 target_format(target, target_buf, sizeof(target_buf)),
                 strerror(errno));
        close(fd);
        return false;
    }
    struct sockaddr_storage local_storage;
    socklen_t local_len = sizeof(local_storage);
    if (getsockname(fd, (struct sockaddr *)&local_storage, &local_len) != 0 ||
        !vane_addr_from_sockaddr((struct sockaddr *)&local_storage, local_len,
                                   &out->local)) {
        LOG_WARN("UDP worker %zu flow=%zu getsockname failed: %s",
                 worker->args->worker_index, id, strerror(errno));
        close(fd);
        return false;
    }
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.u64 = udp_event_token(UDP_EVENT_UPSTREAM, (uint32_t)id,
                                    generation),
    };
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        LOG_WARN("UDP worker %zu flow=%zu upstream epoll add failed: %s",
                 worker->args->worker_index, id, strerror(errno));
        close(fd);
        return false;
    }
    out->fd = fd;
    out->gro = gro;
    return true;
}

static void release_probe_accounting(struct udp_worker *worker,
                                     struct udp_flow *flow) {
    if (flow->probe_accounted && worker->pending_count != 0U)
        worker->pending_count--;
    flow->probe_accounted = false;
    flow->probe_activity_ms = 0U;
}

static uint32_t next_generation(uint32_t generation) {
    generation++;
    return generation == 0U ? 1U : generation;
}

bool udp_flow_activate(struct udp_worker *worker, size_t id,
                       const struct vane_target_config *target) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_PENDING || target == NULL ||
        target->location_kind == VANE_LOCATION_DROP) {
        udp_flow_remove(worker, id);
        return false;
    }

    struct udp_upstream_socket upstream;
    if (!open_upstream_socket(worker, id, target, flow->generation, &upstream)) {
        udp_flow_remove(worker, id);
        return false;
    }

    release_probe_accounting(worker, flow);
    flow->state = UDP_FLOW_ACTIVE;
    flow->target = target;
    flow->upstream_fd = upstream.fd;
    flow->upstream_local = upstream.local;
    flow->gso_enabled = true;
    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_DEBUG("UDP worker %zu flow=%zu activated client=%s upstream=%s source=%s "
              "proxy_protocol=%s gro=%s",
              worker->args->worker_index, id,
              vane_addr_format(&flow->key.client, client_buf,
                                 sizeof(client_buf)),
              target_format(target, target_buf, sizeof(target_buf)),
              vane_addr_format(&flow->upstream_local, source_buf,
                                 sizeof(source_buf)),
              target->proxy_protocol ? "on" : "off",
              upstream.gro > 0 ? "on" : "off");
    flow->last_activity_ms = vane_monotonic_ms();
    return true;
}

static bool cid_equal(const uint8_t *a, size_t a_len,
                      const uint8_t *b, size_t b_len) {
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

bool udp_flow_quic_identity_matches(
    const struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity) {
    if (flow == NULL || identity == NULL || !flow->has_quic_identity)
        return false;
    if (vane_quic_initial_identity_equal(&flow->quic_identity, identity))
        return true;
    return flow->has_quic_retry_dcid &&
           flow->quic_identity.version == identity->version &&
           cid_equal(flow->quic_identity.source_connection_id,
                     flow->quic_identity.source_connection_id_len,
                     identity->source_connection_id,
                     identity->source_connection_id_len) &&
           cid_equal(flow->quic_retry_dcid, flow->quic_retry_dcid_len,
                     identity->destination_connection_id,
                     identity->destination_connection_id_len);
}

bool udp_flow_quic_identity_retired(
    const struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity, uint64_t now) {
    if (flow == NULL || identity == NULL) return false;
    for (size_t i = 0U; i < UDP_RETIRED_IDENTITIES; i++) {
        if (flow->retired[i].expires_ms > now &&
            vane_quic_initial_identity_equal(&flow->retired[i].identity,
                                                identity))
            return true;
    }
    return false;
}

static void retire_identity(struct udp_flow *flow,
                            const struct vane_quic_initial_identity *identity,
                            uint64_t now) {
    size_t slot = flow->retired_next;
    flow->retired[slot].identity = *identity;
    flow->retired[slot].expires_ms = now + UDP_RETIRED_IDENTITY_MS;
    flow->retired_next = (slot + 1U) % UDP_RETIRED_IDENTITIES;
}

void udp_flow_set_quic_identity(
    struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity) {
    if (flow == NULL) return;
    if (identity != NULL && flow->has_quic_identity &&
        !udp_flow_quic_identity_matches(flow, identity)) {
        uint64_t now = vane_monotonic_ms();
        retire_identity(flow, &flow->quic_identity, now);
        if (flow->has_quic_retry_dcid) {
            struct vane_quic_initial_identity retry = flow->quic_identity;
            retry.destination_connection_id_len = flow->quic_retry_dcid_len;
            memcpy(retry.destination_connection_id, flow->quic_retry_dcid,
                   flow->quic_retry_dcid_len);
            retire_identity(flow, &retry, now);
        }
    }
    if (identity == NULL) {
        flow->has_quic_identity = false;
        memset(&flow->quic_identity, 0, sizeof(flow->quic_identity));
    } else {
        flow->quic_identity = *identity;
        flow->has_quic_identity = true;
    }
    flow->has_quic_retry_dcid = false;
    flow->quic_retry_dcid_len = 0U;
    memset(flow->quic_retry_dcid, 0, sizeof(flow->quic_retry_dcid));
}

void udp_flow_note_quic_retry(
    struct udp_flow *flow,
    const struct vane_quic_initial_identity *server_identity) {
    if (flow == NULL || server_identity == NULL || !flow->has_quic_identity ||
        flow->quic_identity.version != server_identity->version ||
        !cid_equal(flow->quic_identity.source_connection_id,
                   flow->quic_identity.source_connection_id_len,
                   server_identity->destination_connection_id,
                   server_identity->destination_connection_id_len))
        return;
    flow->quic_retry_dcid_len = server_identity->source_connection_id_len;
    if (flow->quic_retry_dcid_len != 0U)
        memcpy(flow->quic_retry_dcid,
               server_identity->source_connection_id,
               flow->quic_retry_dcid_len);
    flow->has_quic_retry_dcid = true;
}

bool udp_flow_begin_reprobe(
    struct udp_worker *worker, size_t id,
    const struct vane_quic_initial_identity *identity) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state == UDP_FLOW_QUIESCENT && !udp_flow_resume(worker, id))
        return false;
    if (flow->state != UDP_FLOW_ACTIVE || flow->upstream_fd < 0 ||
        flow->target == NULL || identity == NULL ||
        worker->pending_count >= worker->pending_limit)
        return false;

    flow->state = UDP_FLOW_REPROBING;
    flow->reprobe_identity = *identity;
    flow->probe_accounted = true;
    flow->probe_activity_ms = vane_monotonic_ms();
    worker->pending_count++;
    return true;
}

bool udp_flow_commit_reprobe(struct udp_worker *worker, size_t id,
                             const struct vane_target_config *target) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_REPROBING) return false;
    /* A denied or unroutable candidate must not tear down the established
     * flow. The caller cancels the side probe and restores ACTIVE state. */
    if (target == NULL || target->location_kind == VANE_LOCATION_DROP)
        return false;

    if (target == flow->target) {
        release_probe_accounting(worker, flow);
        memset(&flow->reprobe_identity, 0, sizeof(flow->reprobe_identity));
        flow->state = UDP_FLOW_ACTIVE;
        flow->upstream_confirmed = false;
        udp_flow_clear_error_history(flow);
        flow->last_activity_ms = vane_monotonic_ms();
        return true;
    }

    uint32_t generation = next_generation(flow->generation);
    struct udp_upstream_socket replacement;
    if (!open_upstream_socket(worker, id, target, generation, &replacement))
        return false;

    int old_fd = flow->upstream_fd;
    (void)epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, old_fd, NULL);
    close(old_fd);

    release_probe_accounting(worker, flow);
    memset(&flow->reprobe_identity, 0, sizeof(flow->reprobe_identity));
    flow->generation = generation;
    flow->state = UDP_FLOW_ACTIVE;
    flow->target = target;
    flow->upstream_fd = replacement.fd;
    flow->upstream_local = replacement.local;
    flow->gso_enabled = true;
    flow->upstream_confirmed = false;
    udp_flow_clear_error_history(flow);
    flow->last_activity_ms = vane_monotonic_ms();

    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_DEBUG("UDP worker %zu flow=%zu retargeted client=%s upstream=%s source=%s "
              "proxy_protocol=%s gro=%s",
              worker->args->worker_index, id,
              vane_addr_format(&flow->key.client, client_buf,
                                 sizeof(client_buf)),
              target_format(target, target_buf, sizeof(target_buf)),
              vane_addr_format(&flow->upstream_local, source_buf,
                                 sizeof(source_buf)),
              target->proxy_protocol ? "on" : "off",
              replacement.gro > 0 ? "on" : "off");
    return true;
}

void udp_flow_cancel_reprobe(struct udp_worker *worker, size_t id,
                             const char *reason) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_REPROBING) return;
    udp_probe_destroy(worker, flow);
    release_probe_accounting(worker, flow);
    memset(&flow->reprobe_identity, 0, sizeof(flow->reprobe_identity));
    flow->state = UDP_FLOW_ACTIVE;
    LOG_DEBUG("UDP worker %zu flow=%zu QUIC reprobe cancelled reason=%s",
              worker->args->worker_index, id,
              reason != NULL ? reason : "unknown");
}

static bool udp_error_preserves_socket(int error_number) {
    switch (error_number) {
        case ECONNREFUSED:
        case ECONNRESET:
        case EHOSTUNREACH:
        case ENETUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
        case ETIMEDOUT:
        case EACCES:
        case EPERM:
        case EMSGSIZE:
        case EPIPE:
            return true;
        default:
            return false;
    }
}

static const char *flow_state_name(enum udp_flow_state state) {
    switch (state) {
        case UDP_FLOW_PENDING: return "pending";
        case UDP_FLOW_ACTIVE: return "active";
        case UDP_FLOW_REPROBING: return "reprobing";
        case UDP_FLOW_QUIESCENT: return "quiescent";
        default: return "empty";
    }
}

static void log_io_error(struct udp_worker *worker, size_t id,
                         const char *operation, int error_number) {
    struct udp_flow *flow = &worker->flows[id];
    uint64_t now = vane_monotonic_ms();
    if (flow->last_error == error_number &&
        now - flow->last_error_log_ms < UDP_ERROR_LOG_INTERVAL_MS) {
        if (flow->suppressed_errors != UINT32_MAX) flow->suppressed_errors++;
        return;
    }
    if (flow->last_error != error_number) flow->suppressed_errors = 0U;

    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_WARN("UDP worker %zu flow=%zu state=%s client=%s target=%s source=%s "
             "%s failed: errno=%d %s (suppressed=%u, socket kept)",
             worker->args->worker_index, id, flow_state_name(flow->state),
             vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
             target_format(flow->target, target_buf, sizeof(target_buf)),
             vane_addr_format(&flow->upstream_local, source_buf, sizeof(source_buf)),
             operation, error_number, strerror(error_number),
             flow->suppressed_errors);
    flow->last_error = error_number;
    flow->last_error_log_ms = now;
    flow->suppressed_errors = 0U;
}

bool udp_flow_handle_io_error(struct udp_worker *worker, size_t id,
                              const char *operation, int error_number) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_ACTIVE &&
        flow->state != UDP_FLOW_REPROBING &&
        flow->state != UDP_FLOW_QUIESCENT)
        return false;

    errno = error_number;
    if (flow->upstream_confirmed && udp_error_preserves_socket(error_number)) {
        log_io_error(worker, id, operation, error_number);
        return true;
    }

    char client_buf[96];
    char target_buf[96];
    char source_buf[96];
    LOG_WARN("UDP worker %zu flow=%zu state=%s client=%s target=%s source=%s "
             "%s failed: errno=%d %s (flow removed)",
             worker->args->worker_index, id, flow_state_name(flow->state),
             vane_addr_format(&flow->key.client, client_buf, sizeof(client_buf)),
             target_format(flow->target, target_buf, sizeof(target_buf)),
             vane_addr_format(&flow->upstream_local, source_buf, sizeof(source_buf)),
             operation, error_number, strerror(error_number));
    udp_flow_remove(worker, id);
    return false;
}

void udp_flow_handle_epoll_error(struct udp_worker *worker, size_t id,
                                 uint32_t events) {
    struct udp_flow *flow = &worker->flows[id];
    if (flow->state != UDP_FLOW_ACTIVE &&
        flow->state != UDP_FLOW_REPROBING &&
        flow->state != UDP_FLOW_QUIESCENT)
        return;

    int socket_error = 0;
    socklen_t error_len = sizeof(socket_error);
    if (getsockopt(flow->upstream_fd, SOL_SOCKET, SO_ERROR,
                   &socket_error, &error_len) != 0) {
        int saved = errno;
        (void)udp_flow_handle_io_error(worker, id, "upstream SO_ERROR", saved);
        return;
    }
    if (socket_error != 0) {
        (void)udp_flow_handle_io_error(worker, id, "upstream asynchronous error",
                                       socket_error);
        return;
    }
    if ((events & EPOLLHUP) != 0U) {
        LOG_WARN("UDP worker %zu flow=%zu upstream EPOLLHUP without SO_ERROR "
                 "(flow removed)", worker->args->worker_index, id);
        udp_flow_remove(worker, id);
    }
}

void udp_flow_expire(struct udp_worker *worker) {
    uint64_t now = vane_monotonic_ms();
    if (now < worker->next_expiry_scan_ms) return;
    worker->next_expiry_scan_ms = now + 1000U;

    for (size_t i = 0; i < worker->flow_capacity; i++) {
        struct udp_flow *flow = &worker->flows[i];
        if (flow->state == UDP_FLOW_EMPTY) continue;

        uint64_t idle = now - flow->last_activity_ms;
        if (flow->state == UDP_FLOW_REPROBING) {
            uint64_t probe_idle = now - flow->probe_activity_ms;
            if (probe_idle >= worker->args->runtime->udp_probe_timeout_ms)
                udp_flow_cancel_reprobe(worker, i, "timeout");
            continue;
        }
        if (flow->state == UDP_FLOW_PENDING) {
            if (idle < worker->args->runtime->udp_probe_timeout_ms) continue;
        } else if (!flow->upstream_confirmed) {
            if (idle < worker->args->runtime->udp_unconfirmed_idle_timeout_ms)
                continue;
        } else {
            if (idle >=
                worker->args->runtime->udp_flow_hard_idle_timeout_ms) {
                char client_buf[96];
                char target_buf[96];
                char source_buf[96];
                LOG_DEBUG("UDP worker %zu flow=%zu hard-idle->empty client=%s "
                          "target=%s source=%s idle_ms=%llu",
                          worker->args->worker_index, i,
                          vane_addr_format(&flow->key.client, client_buf,
                                             sizeof(client_buf)),
                          target_format(flow->target, target_buf,
                                        sizeof(target_buf)),
                          vane_addr_format(&flow->upstream_local, source_buf,
                                             sizeof(source_buf)),
                          (unsigned long long)idle);
                udp_flow_remove(worker, i);
                continue;
            }
            if (flow->state == UDP_FLOW_ACTIVE &&
                idle >= worker->args->runtime->udp_flow_quiescent_after_ms) {
                udp_flow_quiesce(worker, i);
            }
            continue;
        }

        LOG_TRACE("UDP worker %zu flow=%zu expired state=%s idle_ms=%llu",
                  worker->args->worker_index, i,
                  flow_state_name(flow->state),
                  (unsigned long long)idle);
        udp_flow_remove(worker, i);
    }

    udp_flow_manage_capacity(worker, now);
}
