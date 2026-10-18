#ifndef VANE_CONFIG_H
#define VANE_CONFIG_H

#include "vane/address.h"

#include <stddef.h>

enum vane_transport {
    VANE_TRANSPORT_TCP = 1,
    VANE_TRANSPORT_UDP = 2,
};

enum vane_log_level {
    VANE_LOG_ERROR = 0,
    VANE_LOG_WARN = 1,
    VANE_LOG_INFO = 2,
    VANE_LOG_DEBUG = 3,
    VANE_LOG_TRACE = 4,
};

enum vane_location_kind {
    VANE_LOCATION_DROP = 0,
    VANE_LOCATION_ADDRESS = 1,
};

enum vane_sni_kind {
    VANE_SNI_NONE = 0,
    VANE_SNI_ANY = 1,
    VANE_SNI_EXACT = 2,
    VANE_SNI_WILDCARD = 3,
};

struct vane_sni_rule {
    enum vane_sni_kind kind;
    char *hostname;
};

struct vane_target_config {
    enum vane_location_kind location_kind;
    struct vane_addr location;
    bool proxy_protocol;
    struct vane_sni_rule *sni;
    size_t sni_count;
};

struct vane_listener_config {
    struct vane_addr address;
    enum vane_transport transport;
    struct vane_target_config *targets;
    size_t target_count;
};

struct vane_runtime_config {
    size_t workers;
    size_t tcp_max_connections;
    size_t tcp_max_connecting;
    size_t tcp_listen_backlog;
    size_t tcp_relay_buffer_bytes;
    uint64_t tcp_keepalive_idle_secs;
    uint64_t tcp_keepalive_interval_secs;
    size_t udp_flow_capacity;
    size_t udp_max_pending_probes;
    size_t tcp_probe_buffer_bytes;
    uint64_t tcp_probe_timeout_ms;
    uint64_t tcp_connect_timeout_ms;
    uint64_t tcp_half_close_idle_timeout_ms;
    uint64_t udp_probe_timeout_ms;
    uint64_t udp_unconfirmed_idle_timeout_ms;
    uint64_t udp_flow_quiescent_after_ms;
    uint64_t udp_flow_hard_idle_timeout_ms;
    size_t udp_probe_max_datagrams;
    size_t udp_probe_max_bytes;
    size_t socket_recv_buffer_bytes;
    size_t socket_send_buffer_bytes;
    size_t upstream_recv_buffer_bytes;
    size_t upstream_send_buffer_bytes;
    size_t recv_batch;
    size_t send_batch;
};

struct vane_config {
    enum vane_log_level log_level;
    struct vane_runtime_config runtime;
    struct vane_listener_config *listeners;
    size_t listener_count;
};

void vane_config_defaults(struct vane_config *config);
bool vane_config_load(const char *path, struct vane_config *out,
                        struct vane_error *err);
void vane_config_destroy(struct vane_config *config);

#endif
