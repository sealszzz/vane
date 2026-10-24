#include "vane/tls_parser.h"

#include <assert.h>
#include <string.h>

static size_t make_hello(uint8_t *out, const char *host) {
    size_t hlen = strlen(host);
    uint8_t body[512];
    size_t p = 0;
    body[p++] = 0x03; body[p++] = 0x03;
    memset(body + p, 0, 32); p += 32;
    body[p++] = 0;
    body[p++] = 0; body[p++] = 2; body[p++] = 0x13; body[p++] = 0x01;
    body[p++] = 1; body[p++] = 0;
    size_t ext_len = 4 + 2 + 1 + 2 + hlen;
    body[p++] = (uint8_t)(ext_len >> 8); body[p++] = (uint8_t)ext_len;
    body[p++] = 0; body[p++] = 0;
    size_t sni_ext = 2 + 1 + 2 + hlen;
    body[p++] = (uint8_t)(sni_ext >> 8); body[p++] = (uint8_t)sni_ext;
    size_t list = 1 + 2 + hlen;
    body[p++] = (uint8_t)(list >> 8); body[p++] = (uint8_t)list;
    body[p++] = 0; body[p++] = (uint8_t)(hlen >> 8); body[p++] = (uint8_t)hlen;
    memcpy(body + p, host, hlen); p += hlen;

    size_t q = 0;
    out[q++] = 0x16; out[q++] = 0x03; out[q++] = 0x03;
    size_t record_len = 4 + p;
    out[q++] = (uint8_t)(record_len >> 8); out[q++] = (uint8_t)record_len;
    out[q++] = 1; out[q++] = (uint8_t)(p >> 16); out[q++] = (uint8_t)(p >> 8); out[q++] = (uint8_t)p;
    memcpy(out + q, body, p); q += p;
    return q;
}

int main(void) {
    uint8_t wire[1024];
    size_t len = make_hello(wire, "Example.COM");
    struct vane_client_hello hello;
    struct vane_error err = {0};
    assert(vane_tls_parse_records(wire, len, &hello, &err) == VANE_PROBE_MATCHED);
    assert(hello.has_sni);
    assert(strcmp(hello.server_name, "example.com") == 0);
    assert(vane_tls_parse_records(wire, 4, &hello, &err) == VANE_PROBE_NEED_MORE);

    /* Re-encode the same ClientHello across two TLS records. */
    const size_t split = 11U;
    const size_t handshake_len = len - 5U;
    uint8_t fragmented[1100];
    size_t f = 0U;
    fragmented[f++] = 0x16; fragmented[f++] = 0x03; fragmented[f++] = 0x03;
    fragmented[f++] = (uint8_t)(split >> 8); fragmented[f++] = (uint8_t)split;
    memcpy(fragmented + f, wire + 5U, split); f += split;
    size_t tail = handshake_len - split;
    fragmented[f++] = 0x16; fragmented[f++] = 0x03; fragmented[f++] = 0x03;
    fragmented[f++] = (uint8_t)(tail >> 8); fragmented[f++] = (uint8_t)tail;
    memcpy(fragmented + f, wire + 5U + split, tail); f += tail;
    assert(vane_tls_parse_records(fragmented, f, &hello, &err) == VANE_PROBE_MATCHED);
    assert(strcmp(hello.server_name, "example.com") == 0);

    for (size_t first = 0U; first < handshake_len; first++) {
        size_t at = 0U;
        size_t portions[3] = {first, 1U, handshake_len - first - 1U};
        size_t source = 5U;
        for (size_t i = 0U; i < 3U; i++) {
            size_t n = portions[i];
            fragmented[at++] = 0x16U;
            fragmented[at++] = 0x03U;
            fragmented[at++] = 0x03U;
            fragmented[at++] = (uint8_t)(n >> 8);
            fragmented[at++] = (uint8_t)n;
            memcpy(fragmented + at, wire + source, n);
            at += n;
            source += n;
        }
        for (size_t partial = 0U; partial < at; partial++) {
            enum vane_probe_result result =
                vane_tls_parse_records(fragmented, partial, &hello, &err);
            /* A zero final record is not needed once the hello is complete. */
            assert(result == VANE_PROBE_NEED_MORE ||
                   (portions[2] == 0U && partial >= at - 5U &&
                    result == VANE_PROBE_MATCHED));
        }
        assert(vane_tls_parse_records(fragmented, at, &hello, &err) == VANE_PROBE_MATCHED);
        assert(strcmp(hello.server_name, "example.com") == 0);
    }

    /* A present server_name extension must contain a non-empty list. */
    uint8_t empty_list[1024];
    memcpy(empty_list, wire, len);
    const uint8_t host_bytes[] = "Example.COM";
    uint8_t *host_pos = memmem(empty_list, len, host_bytes, sizeof(host_bytes) - 1U);
    assert(host_pos != NULL && host_pos >= empty_list + 5U);
    host_pos[-5] = 0U;
    host_pos[-4] = 0U;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(empty_list, len, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    /* The ServerNameList must consume the complete server_name extension. */
    uint8_t trailing[1024];
    memcpy(trailing, wire, len);
    host_pos = memmem(trailing, len, host_bytes, sizeof(host_bytes) - 1U);
    assert(host_pos != NULL && host_pos >= trailing + 11U);
    uint16_t record_len = (uint16_t)((uint16_t)trailing[3] << 8 | trailing[4]);
    record_len++;
    trailing[3] = (uint8_t)(record_len >> 8);
    trailing[4] = (uint8_t)record_len;
    uint32_t body_len = (uint32_t)trailing[6] << 16 |
                        (uint32_t)trailing[7] << 8 | trailing[8];
    body_len++;
    trailing[6] = (uint8_t)(body_len >> 16);
    trailing[7] = (uint8_t)(body_len >> 8);
    trailing[8] = (uint8_t)body_len;
    uint16_t extensions_len = (uint16_t)((uint16_t)host_pos[-11] << 8 |
                                         host_pos[-10]);
    extensions_len++;
    host_pos[-11] = (uint8_t)(extensions_len >> 8);
    host_pos[-10] = (uint8_t)extensions_len;
    uint16_t sni_len = (uint16_t)((uint16_t)host_pos[-7] << 8 | host_pos[-6]);
    sni_len++;
    host_pos[-7] = (uint8_t)(sni_len >> 8);
    host_pos[-6] = (uint8_t)sni_len;
    trailing[len] = 0xa5U;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(trailing, len + 1U, &hello, &err) ==
           VANE_PROBE_MALFORMED);


    /* Structural ClientHello vectors must obey their protocol bounds. */
    uint8_t malformed[1024];
    memcpy(malformed, wire, len);
    malformed[43] = 33U;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(malformed, len, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    memcpy(malformed, wire, len);
    malformed[44] = 0U;
    malformed[45] = 3U;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(malformed, len, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    memcpy(malformed, wire, len);
    malformed[48] = 0U;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(malformed, len, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    /* The extension vector must consume the rest of ClientHello exactly. */
    memcpy(malformed, wire, len);
    record_len = (uint16_t)((uint16_t)malformed[3] << 8 | malformed[4]);
    record_len++;
    malformed[3] = (uint8_t)(record_len >> 8);
    malformed[4] = (uint8_t)record_len;
    body_len = (uint32_t)malformed[6] << 16 |
               (uint32_t)malformed[7] << 8 | malformed[8];
    body_len++;
    malformed[6] = (uint8_t)(body_len >> 16);
    malformed[7] = (uint8_t)(body_len >> 8);
    malformed[8] = (uint8_t)body_len;
    malformed[len] = 0x5aU;
    memset(&err, 0, sizeof(err));
    assert(vane_tls_parse_records(malformed, len + 1U, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    const uint8_t http[] = "GET / HTTP/1.0\r\n\r\n";
    assert(vane_tls_parse_records(http, sizeof(http) - 1, &hello, &err) == VANE_PROBE_NOT_PROTOCOL);
    return 0;
}
