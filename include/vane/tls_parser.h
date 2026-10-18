#ifndef VANE_TLS_PARSER_H
#define VANE_TLS_PARSER_H

#include "vane/common.h"

enum vane_probe_result {
    VANE_PROBE_MATCHED = 0,
    VANE_PROBE_NEED_MORE = 1,
    VANE_PROBE_NOT_PROTOCOL = 2,
    VANE_PROBE_MALFORMED = 3,
};

struct vane_client_hello {
    bool has_sni;
    size_t server_name_len;
    char server_name[VANE_MAX_SNI_LEN + 1U];
};

enum vane_probe_result
vane_tls_parse_records(const uint8_t *data, size_t len,
                         struct vane_client_hello *hello,
                         struct vane_error *err);

enum vane_probe_result
vane_tls_parse_handshake(const uint8_t *data, size_t len,
                           struct vane_client_hello *hello,
                           struct vane_error *err);

#endif
