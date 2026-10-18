#include "vane/tls_parser.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define TLS_HEADER_LEN 5U
#define TLS_CONTENT_HANDSHAKE 0x16U
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01U
#define TLS_EXT_SERVER_NAME 0x0000U

static bool need(size_t len, size_t pos, size_t n) {
    return pos <= len && n <= len - pos;
}

static bool read_u8(const uint8_t *buf, size_t len, size_t *pos, uint8_t *out) {
    if (!need(len, *pos, 1)) return false;
    *out = buf[(*pos)++];
    return true;
}

static bool read_u16(const uint8_t *buf, size_t len, size_t *pos, uint16_t *out) {
    if (!need(len, *pos, 2)) return false;
    *out = (uint16_t)((uint16_t)buf[*pos] << 8 | buf[*pos + 1]);
    *pos += 2;
    return true;
}

static bool read_u24(const uint8_t *buf, size_t len, size_t *pos, uint32_t *out) {
    if (!need(len, *pos, 3)) return false;
    *out = (uint32_t)buf[*pos] << 16 | (uint32_t)buf[*pos + 1] << 8 |
           (uint32_t)buf[*pos + 2];
    *pos += 3;
    return true;
}

static bool hostname_copy_lower(const uint8_t *src, size_t len,
                                struct vane_client_hello *hello,
                                struct vane_error *err) {
    if (len == 0 || len > VANE_MAX_SNI_LEN) {
        vane_error_set(err, "TLS SNI hostname length is invalid");
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        if (c < 0x21U || c > 0x7eU) {
            vane_error_set(err, "TLS SNI hostname is not printable ASCII");
            return false;
        }
        hello->server_name[i] = (char)tolower(c);
    }
    while (len > 0 && hello->server_name[len - 1] == '.') len--;
    if (len == 0) {
        vane_error_set(err, "TLS SNI hostname is empty");
        return false;
    }
    hello->server_name[len] = '\0';
    hello->server_name_len = len;
    hello->has_sni = true;
    return true;
}

enum vane_probe_result
vane_tls_parse_handshake(const uint8_t *data, size_t len,
                           struct vane_client_hello *hello,
                           struct vane_error *err) {
    if (data == NULL || hello == NULL) return VANE_PROBE_MALFORMED;
    memset(hello, 0, sizeof(*hello));
    size_t pos = 0;
    uint8_t type = 0;
    uint32_t body_len = 0;
    if (!read_u8(data, len, &pos, &type) || !read_u24(data, len, &pos, &body_len))
        return VANE_PROBE_NEED_MORE;
    if (type != TLS_HANDSHAKE_CLIENT_HELLO) {
        vane_error_set(err, "TLS handshake is not ClientHello");
        return VANE_PROBE_MALFORMED;
    }
    if (body_len > VANE_TLS_HANDSHAKE_MAX_SIZE - 4U) {
        vane_error_set(err, "TLS ClientHello exceeds probe limit");
        return VANE_PROBE_MALFORMED;
    }
    if (!need(len, pos, body_len)) return VANE_PROBE_NEED_MORE;
    size_t end = pos + body_len;
    uint16_t legacy_version = 0, list_len = 0;
    uint8_t one_len = 0;
    if (!read_u16(data, end, &pos, &legacy_version) || !need(end, pos, 32)) goto invalid;
    VANE_UNUSED(legacy_version);
    pos += 32;
    if (!read_u8(data, end, &pos, &one_len)) goto invalid;
    if (one_len > 32U) {
        vane_error_set(err, "TLS legacy session ID exceeds 32 bytes");
        return VANE_PROBE_MALFORMED;
    }
    if (!need(end, pos, one_len)) goto invalid;
    pos += one_len;
    if (!read_u16(data, end, &pos, &list_len)) goto invalid;
    if (list_len < 2U || (list_len & 1U) != 0U) {
        vane_error_set(err, "TLS cipher suite list length is invalid");
        return VANE_PROBE_MALFORMED;
    }
    if (!need(end, pos, list_len)) goto invalid;
    pos += list_len;
    if (!read_u8(data, end, &pos, &one_len)) goto invalid;
    if (one_len == 0U) {
        vane_error_set(err, "TLS compression method list is empty");
        return VANE_PROBE_MALFORMED;
    }
    if (!need(end, pos, one_len)) goto invalid;
    pos += one_len;
    if (pos == end) return VANE_PROBE_MATCHED;
    if (!read_u16(data, end, &pos, &list_len) || !need(end, pos, list_len)) goto invalid;
    size_t extensions_end = pos + list_len;
    if (extensions_end != end) {
        vane_error_set(err, "TLS extension list length does not match ClientHello");
        return VANE_PROBE_MALFORMED;
    }
    bool saw_sni = false;
    while (pos < extensions_end) {
        uint16_t ext_type = 0, ext_len = 0;
        if (!read_u16(data, extensions_end, &pos, &ext_type) ||
            !read_u16(data, extensions_end, &pos, &ext_len) ||
            !need(extensions_end, pos, ext_len)) goto invalid;
        size_t ext_end = pos + ext_len;
        if (ext_type != TLS_EXT_SERVER_NAME) {
            pos = ext_end;
            continue;
        }
        if (saw_sni) {
            vane_error_set(err, "duplicate TLS SNI extension");
            return VANE_PROBE_MALFORMED;
        }
        saw_sni = true;
        uint16_t names_len = 0;
        if (!read_u16(data, ext_end, &pos, &names_len) || names_len == 0U ||
            !need(ext_end, pos, names_len)) {
            vane_error_set(err, "TLS SNI list is empty or truncated");
            return VANE_PROBE_MALFORMED;
        }
        size_t names_end = pos + names_len;
        if (names_end != ext_end) {
            vane_error_set(err, "TLS SNI list length does not match extension length");
            return VANE_PROBE_MALFORMED;
        }
        bool saw_host_name = false;
        while (pos < names_end) {
            uint8_t name_type = 0;
            uint16_t name_len = 0;
            if (!read_u8(data, names_end, &pos, &name_type) ||
                !read_u16(data, names_end, &pos, &name_len) ||
                !need(names_end, pos, name_len)) {
                vane_error_set(err, "TLS SNI entry exceeds list boundary");
                return VANE_PROBE_MALFORMED;
            }
            if (name_type == 0) {
                if (saw_host_name) {
                    vane_error_set(err, "duplicate TLS host_name entry");
                    return VANE_PROBE_MALFORMED;
                }
                saw_host_name = true;
                if (!hostname_copy_lower(data + pos, name_len, hello, err))
                    return VANE_PROBE_MALFORMED;
            }
            pos += name_len;
        }
        if (pos != names_end) {
            vane_error_set(err, "TLS SNI list parsing overrun");
            return VANE_PROBE_MALFORMED;
        }
        pos = ext_end;
    }
    if (pos != extensions_end) {
        vane_error_set(err, "TLS extension parsing overrun");
        return VANE_PROBE_MALFORMED;
    }
    return VANE_PROBE_MATCHED;
invalid:
    vane_error_set(err, "TLS ClientHello structure exceeds declared body");
    return VANE_PROBE_MALFORMED;
}

static enum vane_probe_result parse_single_record(const uint8_t *data, size_t len,
                                                     struct vane_client_hello *hello,
                                                     struct vane_error *err) {
    if (len < TLS_HEADER_LEN) return VANE_PROBE_NEED_MORE;
    if (data[0] != TLS_CONTENT_HANDSHAKE) return VANE_PROBE_NOT_PROTOCOL;
    if (data[1] != 3U || data[2] > 4U) return VANE_PROBE_NOT_PROTOCOL;
    size_t payload_len = (size_t)((uint16_t)data[3] << 8 | data[4]);
    if (!need(len, TLS_HEADER_LEN, payload_len)) return VANE_PROBE_NEED_MORE;
    if (payload_len < 4U) return VANE_PROBE_NEED_MORE;
    const uint8_t *payload = data + TLS_HEADER_LEN;
    if (payload[0] != TLS_HANDSHAKE_CLIENT_HELLO) return VANE_PROBE_MALFORMED;
    size_t handshake_len = (size_t)payload[1] << 16 | (size_t)payload[2] << 8 | payload[3];
    if (handshake_len > VANE_TLS_HANDSHAKE_MAX_SIZE - 4U) {
        vane_error_set(err, "TLS ClientHello exceeds probe limit");
        return VANE_PROBE_MALFORMED;
    }
    if (payload_len < handshake_len + 4U) return VANE_PROBE_NEED_MORE;
    return vane_tls_parse_handshake(payload, handshake_len + 4U, hello, err);
}

enum vane_probe_result
vane_tls_parse_records(const uint8_t *data, size_t len,
                         struct vane_client_hello *hello,
                         struct vane_error *err) {
    enum vane_probe_result fast = parse_single_record(data, len, hello, err);
    if (fast == VANE_PROBE_MATCHED || fast == VANE_PROBE_NOT_PROTOCOL ||
        fast == VANE_PROBE_MALFORMED) return fast;
    if (len < TLS_HEADER_LEN) return VANE_PROBE_NEED_MORE;
    if (data[0] != TLS_CONTENT_HANDSHAKE) return VANE_PROBE_NOT_PROTOCOL;
    size_t first_record_len = (size_t)((uint16_t)data[3] << 8 | data[4]);
    if (!need(len, TLS_HEADER_LEN, first_record_len)) return VANE_PROBE_NEED_MORE;

    uint8_t header[4];
    size_t header_len = 0;
    size_t wire = 0;
    size_t expected = 0;
    uint8_t *handshake = NULL;
    size_t collected = 0;
    enum vane_probe_result result = VANE_PROBE_NEED_MORE;

    while (wire < len) {
        if (!need(len, wire, TLS_HEADER_LEN)) break;
        if (data[wire] != TLS_CONTENT_HANDSHAKE || data[wire + 1] != 3U ||
            data[wire + 2] > 4U) {
            vane_error_set(err, "non-handshake TLS record during ClientHello probe");
            result = VANE_PROBE_MALFORMED;
            break;
        }
        size_t record_len = (size_t)((uint16_t)data[wire + 3] << 8 | data[wire + 4]);
        wire += TLS_HEADER_LEN;
        if (!need(len, wire, record_len)) break;
        size_t rp = 0;
        while (rp < record_len) {
            if (header_len < sizeof(header)) {
                size_t take = VANE_MIN(sizeof(header) - header_len,
                                         record_len - rp);
                memcpy(header + header_len, data + wire + rp, take);
                header_len += take;
                rp += take;
                if (header_len < sizeof(header)) continue;
                if (header[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
                    vane_error_set(err, "TLS handshake is not ClientHello");
                    result = VANE_PROBE_MALFORMED;
                    goto done;
                }
                expected = 4U + ((size_t)header[1] << 16) +
                           ((size_t)header[2] << 8) + header[3];
                if (expected > VANE_TLS_HANDSHAKE_MAX_SIZE) {
                    vane_error_set(err, "TLS ClientHello exceeds probe limit");
                    result = VANE_PROBE_MALFORMED;
                    goto done;
                }
                handshake = malloc(expected);
                if (handshake == NULL) {
                    vane_error_set(err, "out of memory");
                    result = VANE_PROBE_MALFORMED;
                    goto done;
                }
                memcpy(handshake, header, sizeof(header));
                collected = sizeof(header);
            }
            size_t missing = expected - collected;
            size_t take = VANE_MIN(missing, record_len - rp);
            memcpy(handshake + collected, data + wire + rp, take);
            collected += take;
            rp += take;
            if (collected == expected) {
                result = vane_tls_parse_handshake(handshake, collected, hello, err);
                goto done;
            }
        }
        wire += record_len;
    }
done:
    if (handshake != NULL) {
        OPENSSL_cleanse(handshake, expected);
        free(handshake);
    }
    return result;
}
