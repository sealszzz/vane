#ifndef VANE_UDP_INTERNAL_H
#define VANE_UDP_INTERNAL_H

#include "workers.h"

#include "vane/linux_net.h"
#include "vane/quic_parser.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define UDP_EVENT_PUBLIC 1U
#define UDP_EVENT_UPSTREAM 2U
#define UDP_EPOLL_BATCH 256
#define UDP_PUBLIC_BATCH_QUANTUM 16U
#define UDP_FLOW_ID_MAX UINT32_C(0x00ffffff)
#define UDP_MAX_PACKET 65535U
#define UDP_GSO_SAFE_BYTES (60U * 1024U)
#define UDP_GSO_MAX_SEGMENTS 64U
#define UDP_PROBE_MAX_DATAGRAMS_HARD 64U
#define UDP_PROBE_INITIAL_BYTES 4096U
#define UDP_PROBE_CACHE_LIMIT 16U
#define UDP_ERROR_LOG_INTERVAL_MS 5000U
#define UDP_FLOW_HIGH_WATER_PERCENT 80U
#define UDP_FLOW_LOW_WATER_PERCENT 65U
#define UDP_RETIRED_IDENTITIES 4U
#define UDP_RETIRED_IDENTITY_MS 120000U
#define UDP_RECEIVE_ERROR_QUANTUM 8U

enum udp_flow_state {
    UDP_FLOW_EMPTY = 0,
    UDP_FLOW_PENDING,
    UDP_FLOW_ACTIVE,
    UDP_FLOW_REPROBING,
    UDP_FLOW_QUIESCENT,
};

struct udp_flow_key {
    struct vane_addr client;
    struct vane_addr local;
};

struct udp_probe {
    struct vane_quic_probe_state *parser;
    uint8_t *data;
    size_t capacity;
    size_t total_bytes;
    size_t count;
    uint32_t offsets[UDP_PROBE_MAX_DATAGRAMS_HARD];
    uint32_t lengths[UDP_PROBE_MAX_DATAGRAMS_HARD];
    uint8_t tclasses[UDP_PROBE_MAX_DATAGRAMS_HARD];
    bool has_tclass[UDP_PROBE_MAX_DATAGRAMS_HARD];
};

struct udp_retired_identity {
    struct vane_quic_initial_identity identity;
    uint64_t expires_ms;
};

struct udp_flow {
    enum udp_flow_state state;
    uint32_t generation;
    struct udp_flow_key key;
    uint64_t last_activity_ms;
    uint64_t probe_activity_ms;
    const struct vane_target_config *target;
    int upstream_fd;
    struct vane_addr upstream_local;
    bool gso_enabled;
    bool upstream_confirmed;
    bool probe_accounted;
    uint32_t probe_id;
    size_t hash_slot;
    uint64_t last_error_log_ms;
    uint32_t suppressed_errors;
    int last_error;
    bool has_quic_identity;
    struct vane_quic_initial_identity quic_identity;
    bool has_quic_retry_dcid;
    uint8_t quic_retry_dcid[VANE_QUIC_MAX_CID_LEN];
    size_t quic_retry_dcid_len;
    struct vane_quic_initial_identity reprobe_identity;
    struct udp_retired_identity retired[UDP_RETIRED_IDENTITIES];
    size_t retired_next;
};

struct udp_flow_index_entry {
    uint32_t flow_id_plus_one;
};

struct udp_reclaim_candidate {
    uint64_t last_activity_ms;
    uint32_t flow_id;
};

struct udp_down_item {
    uint8_t *data;
    size_t len;
    uint16_t segment_size;
    bool has_segment;
    struct vane_addr peer;
    struct vane_addr local;
    uint8_t tclass;
    bool has_tclass;
};

struct udp_worker {
    const struct vane_worker_args *args;
    int epoll_fd;
    int public_fd;
    bool public_gro;
    bool public_gso_enabled;

    struct udp_flow *flows;
    struct udp_flow_index_entry *flow_index;
    uint32_t *free_flow_ids;
    size_t free_flow_count;
    size_t table_capacity;
    size_t flow_capacity;
    size_t flow_base_limit;
    size_t flow_limit;
    size_t flow_count;
    struct udp_reclaim_candidate *reclaim_candidates;
    uint64_t hash_seed;

    size_t pending_count;
    size_t pending_limit;
    struct udp_probe *probes;
    uint32_t *free_probe_ids;
    size_t free_probe_count;
    uint8_t *probe_cache[UDP_PROBE_CACHE_LIMIT];
    size_t probe_cache_count;

    struct mmsghdr *rx_msgs;
    struct iovec *rx_iov;
    struct sockaddr_storage *rx_peers;
    unsigned char *rx_controls;
    uint8_t *rx_storage;
    size_t rx_count;

    struct udp_down_item *down;
    struct mmsghdr *tx_msgs;
    struct iovec *tx_iov;
    unsigned char *tx_controls;
    uint8_t *down_storage;
    size_t down_capacity;
    size_t down_count;

    uint8_t *upstream_rx_storage;
    uint64_t next_expiry_scan_ms;
    uint64_t next_capacity_scan_ms;
};

static inline uint64_t udp_event_token(uint8_t kind, uint32_t id,
                                       uint32_t generation) {
    return ((uint64_t)kind << 56) | ((uint64_t)generation << 24) |
           (uint64_t)(id & UDP_FLOW_ID_MAX);
}

static inline uint8_t udp_token_kind(uint64_t token) {
    return (uint8_t)(token >> 56);
}

static inline uint32_t udp_token_generation(uint64_t token) {
    return (uint32_t)(token >> 24);
}

static inline uint32_t udp_token_id(uint64_t token) {
    return (uint32_t)(token & UDP_FLOW_ID_MAX);
}

static inline void udp_flow_clear_error_history(struct udp_flow *flow) {
    flow->last_error = 0;
    flow->last_error_log_ms = 0U;
    flow->suppressed_errors = 0U;
}

bool udp_gso_error_disables(int error_number);
bool udp_gso_error_allows_fallback(int error_number);

/* Flow table and active-flow lifecycle. */
bool udp_flow_key_equal(const struct udp_flow_key *a,
                        const struct udp_flow_key *b);
size_t udp_next_power_of_two(size_t value);
size_t udp_flow_lookup_id(const struct udp_worker *worker,
                          const struct udp_flow_key *key);
struct udp_flow *udp_flow_insert(struct udp_worker *worker,
                                 const struct udp_flow_key *key,
                                 bool account_probe, size_t *id_out);
void udp_flow_remove(struct udp_worker *worker, size_t id);
bool udp_flow_resume(struct udp_worker *worker, size_t id);
bool udp_flow_handle_io_error(struct udp_worker *worker, size_t id,
                              const char *operation, int error_number);
void udp_flow_handle_epoll_error(struct udp_worker *worker, size_t id,
                                 uint32_t events);
bool udp_flow_activate(struct udp_worker *worker, size_t id,
                       const struct vane_target_config *target);
bool udp_flow_quic_identity_matches(
    const struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity);
bool udp_flow_quic_identity_retired(
    const struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity, uint64_t now);
void udp_flow_set_quic_identity(
    struct udp_flow *flow,
    const struct vane_quic_initial_identity *identity);
void udp_flow_note_quic_retry(
    struct udp_flow *flow,
    const struct vane_quic_initial_identity *server_identity);
bool udp_flow_begin_reprobe(
    struct udp_worker *worker, size_t id,
    const struct vane_quic_initial_identity *identity);
bool udp_flow_commit_reprobe(struct udp_worker *worker, size_t id,
                             const struct vane_target_config *target);
void udp_flow_cancel_reprobe(struct udp_worker *worker, size_t id,
                             const char *reason);
void udp_flow_expire(struct udp_worker *worker);
void udp_log_route_decision(const struct udp_worker *worker, size_t id,
                            const char *classification, const char *sni,
                            const struct vane_target_config *target);

/* Bounded QUIC Initial probe storage and classification. */
struct udp_probe *udp_probe_get(struct udp_worker *worker,
                                const struct udp_flow *flow);
bool udp_probe_append(struct udp_worker *worker, struct udp_flow *flow,
                      const uint8_t *data, size_t len,
                      uint8_t tclass, bool has_tclass);
void udp_probe_destroy(struct udp_worker *worker, struct udp_flow *flow);
void udp_probe_route(struct udp_worker *worker, size_t id);

/* Packet batching and worker-local forwarding. */
void udp_downstream_flush(struct udp_worker *worker);
void udp_downstream_queue(struct udp_worker *worker,
                          const struct udp_flow *flow,
                          const uint8_t *data, size_t len,
                          uint16_t gro_segment_size,
                          uint8_t tclass, bool has_tclass);
bool udp_send_upstream_views(struct udp_flow *flow,
                             const uint8_t *const *packets,
                             size_t count, size_t segment_size,
                             uint8_t tclass, bool has_tclass);
bool udp_send_upstream_aggregate(struct udp_flow *flow,
                                 const uint8_t *data, size_t len,
                                 uint16_t segment_size,
                                 uint8_t tclass, bool has_tclass);
bool udp_forward_upstream(struct udp_worker *worker, size_t id,
                          const uint8_t *data, size_t len,
                          uint8_t tclass, bool has_tclass);
void udp_receive_public(struct udp_worker *worker);
void udp_receive_upstream(struct udp_worker *worker, size_t id);

#endif
