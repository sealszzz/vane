#ifndef VANE_QUIC_PARSER_H
#define VANE_QUIC_PARSER_H

#include "vane/tls_parser.h"

#include <stdint.h>

#define VANE_QUIC_MAX_CID_LEN 20U
#define VANE_QUIC_MIN_INITIAL_DATAGRAM_SIZE 1200U

struct vane_quic_initial_identity {
    uint32_t version;
    uint8_t destination_connection_id[VANE_QUIC_MAX_CID_LEN];
    size_t destination_connection_id_len;
    uint8_t source_connection_id[VANE_QUIC_MAX_CID_LEN];
    size_t source_connection_id_len;
};

struct vane_datagram_view {
    const uint8_t *data;
    size_t len;
};

struct vane_quic_probe_state;

struct vane_quic_probe_state *vane_quic_probe_state_new(void);
void vane_quic_probe_state_free(struct vane_quic_probe_state *state);

enum vane_probe_result
vane_quic_probe_feed(struct vane_quic_probe_state *state,
                       const uint8_t *datagram, size_t datagram_len,
                       struct vane_client_hello *hello,
                       struct vane_error *err);

enum vane_probe_result
vane_quic_parse_client_hello(const struct vane_datagram_view *datagrams,
                               size_t datagram_count,
                               struct vane_client_hello *hello,
                               struct vane_error *err);

bool vane_quic_looks_like_initial(const uint8_t *data, size_t len);
bool vane_quic_looks_like_retry(const uint8_t *data, size_t len);
bool vane_quic_read_long_header_identity(
    const uint8_t *data, size_t len,
    struct vane_quic_initial_identity *identity);
bool vane_quic_read_initial_identity(
    const uint8_t *data, size_t len,
    struct vane_quic_initial_identity *identity);
bool vane_quic_initial_identity_equal(
    const struct vane_quic_initial_identity *a,
    const struct vane_quic_initial_identity *b);

#endif
