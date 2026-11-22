#include "vane/quic_parser.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t quic_v1_salt[20] = {
    0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
};
static const uint8_t quic_v2_salt[20] = {
    0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
    0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9
};
static const uint8_t client_in_label[] = {0x00,0x20,0x0f,'t','l','s','1','3',' ','c','l','i','e','n','t',' ','i','n',0x00};
static const uint8_t key_v1_label[] = {0x00,0x10,0x0e,'t','l','s','1','3',' ','q','u','i','c',' ','k','e','y',0x00};
static const uint8_t iv_v1_label[]  = {0x00,0x0c,0x0d,'t','l','s','1','3',' ','q','u','i','c',' ','i','v',0x00};
static const uint8_t hp_v1_label[]  = {0x00,0x10,0x0d,'t','l','s','1','3',' ','q','u','i','c',' ','h','p',0x00};
static const uint8_t key_v2_label[] = {0x00,0x10,0x10,'t','l','s','1','3',' ','q','u','i','c','v','2',' ','k','e','y',0x00};
static const uint8_t iv_v2_label[]  = {0x00,0x0c,0x0f,'t','l','s','1','3',' ','q','u','i','c','v','2',' ','i','v',0x00};
static const uint8_t hp_v2_label[]  = {0x00,0x10,0x0f,'t','l','s','1','3',' ','q','u','i','c','v','2',' ','h','p',0x00};

enum quic_version { QUIC_V1, QUIC_V2 };

struct protection {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
};

struct protection_cache {
    struct protection keys;
    enum quic_version version;
    uint8_t dcid[20];
    size_t dcid_len;
    bool valid;
};

struct initial_packet {
    enum quic_version version;
    const uint8_t *dcid;
    size_t dcid_len;
    const uint8_t *scid;
    size_t scid_len;
    const uint8_t *token;
    size_t token_len;
    uint8_t *payload;
    size_t payload_len;
};

struct crypto_frame {
    size_t offset;
    const uint8_t *data;
    size_t len;
};

static bool parse_version(const uint8_t *p, enum quic_version *version) {
    if (memcmp(p, "\x00\x00\x00\x01", 4) == 0) {
        *version = QUIC_V1;
        return true;
    }
    if (memcmp(p, "\x6b\x33\x43\xcf", 4) == 0) {
        *version = QUIC_V2;
        return true;
    }
    return false;
}

static bool is_initial(uint8_t first, enum quic_version version) {
    /* The QUIC Bit (0x40) can be cleared per RFC 9287. */
    return (first & 0x30U) == (version == QUIC_V1 ? 0x00U : 0x10U);
}

static bool is_retry(uint8_t first, enum quic_version version) {
    return (first & 0x30U) == (version == QUIC_V1 ? 0x30U : 0x00U);
}

static const uint8_t *read_cid(const uint8_t *data, size_t len, size_t *pos,
                               size_t *cid_len) {
    if (*pos >= len) return NULL;
    *cid_len = data[(*pos)++];
    if (*cid_len > VANE_QUIC_MAX_CID_LEN || *cid_len > len - *pos)
        return NULL;
    const uint8_t *cid = data + *pos;
    *pos += *cid_len;
    return cid;
}

static bool read_varint(const uint8_t *buf, size_t len, size_t *pos, size_t *out) {
    if (*pos >= len) return false;
    uint8_t first = buf[*pos];
    size_t n = (size_t)1U << (first >> 6);
    if (n > len - *pos) return false;
    size_t value = first & 0x3fU;
    (*pos)++;
    for (size_t i = 1; i < n; i++) {
        if (value > (SIZE_MAX >> 8)) return false;
        value = (value << 8) | buf[(*pos)++];
    }
    *out = value;
    return true;
}

static size_t find_initial(const uint8_t *data, size_t len) {
    if (data == NULL) return len;
    size_t pos = 0U;
    while (len - pos >= 5U && (data[pos] & 0x80U) != 0U) {
        enum quic_version version;
        if (!parse_version(data + pos + 1U, &version)) break;
        if (is_initial(data[pos], version)) return pos;
        if (is_retry(data[pos], version)) break;

        /* 0-RTT and Handshake packets carry a Length field after the
         * two CIDs. An Initial may follow either in a coalesced datagram. */
        pos += 5U;
        size_t cid_len, payload_len;
        if (read_cid(data, len, &pos, &cid_len) == NULL ||
            read_cid(data, len, &pos, &cid_len) == NULL ||
            !read_varint(data, len, &pos, &payload_len) ||
            payload_len < 20U || payload_len > len - pos)
            break;
        pos += payload_len;
    }
    return len;
}

bool vane_quic_looks_like_initial(const uint8_t *data, size_t len) {
    return find_initial(data, len) < len;
}

bool vane_quic_looks_like_retry(const uint8_t *data, size_t len) {
    if (data == NULL || len < 5U || (data[0] & 0x80U) == 0U) return false;
    enum quic_version version;
    return parse_version(data + 1, &version) && is_retry(data[0], version);
}

bool vane_quic_read_long_header_identity(
    const uint8_t *data, size_t len,
    struct vane_quic_initial_identity *identity) {
    if (identity == NULL || data == NULL || len < 7U ||
        (data[0] & 0x80U) == 0U)
        return false;
    enum quic_version version;
    if (!parse_version(data + 1, &version)) return false;

    size_t pos = 5U;
    size_t dcid_len, scid_len;
    const uint8_t *dcid = read_cid(data, len, &pos, &dcid_len);
    if (dcid == NULL) return false;
    const uint8_t *scid = read_cid(data, len, &pos, &scid_len);
    if (scid == NULL) return false;

    memset(identity, 0, sizeof(*identity));
    identity->version = ((uint32_t)data[1] << 24) |
                        ((uint32_t)data[2] << 16) |
                        ((uint32_t)data[3] << 8) |
                        (uint32_t)data[4];
    identity->destination_connection_id_len = dcid_len;
    if (dcid_len != 0U)
        memcpy(identity->destination_connection_id, dcid, dcid_len);
    identity->source_connection_id_len = scid_len;
    if (scid_len != 0U)
        memcpy(identity->source_connection_id, scid, scid_len);
    return true;
}

bool vane_quic_read_coalesced_initial_identity(
    const uint8_t *data, size_t len,
    struct vane_quic_initial_identity *identity) {
    size_t offset = find_initial(data, len);
    return offset < len &&
           vane_quic_read_long_header_identity(data + offset, len - offset,
                                               identity);
}

bool vane_quic_read_initial_identity(
    const uint8_t *data, size_t len,
    struct vane_quic_initial_identity *identity) {
    return len >= VANE_QUIC_MIN_INITIAL_DATAGRAM_SIZE &&
           vane_quic_read_coalesced_initial_identity(data, len, identity);
}

bool vane_quic_initial_identity_equal(
    const struct vane_quic_initial_identity *a,
    const struct vane_quic_initial_identity *b) {
    if (a == NULL || b == NULL || a->version != b->version ||
        a->destination_connection_id_len != b->destination_connection_id_len ||
        a->source_connection_id_len != b->source_connection_id_len)
        return false;
    return memcmp(a->destination_connection_id,
                  b->destination_connection_id,
                  a->destination_connection_id_len) == 0 &&
           memcmp(a->source_connection_id, b->source_connection_id,
                  a->source_connection_id_len) == 0;
}

static bool hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t out[32]) {
    unsigned int n = 0;
#ifdef OPENSSL_IS_AWSLC
    return HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, out, &n) != NULL && n == 32U;
#else
    if (salt_len > (size_t)INT_MAX) return false;
    return HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, out, &n) != NULL && n == 32U;
#endif
}

static bool hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    /* QUIC Initial derives at most one SHA-256 block (32 bytes) per label. */
    uint8_t input[256];
    uint8_t digest[32];
    if (info_len >= sizeof(input) || out_len > sizeof(digest)) return false;
    memcpy(input, info, info_len);
    input[info_len] = 1U;
    unsigned int digest_len = 0;
    bool ok = HMAC(EVP_sha256(), prk, 32, input, info_len + 1U,
                   digest, &digest_len) != NULL && digest_len == sizeof(digest);
    if (ok) memcpy(out, digest, out_len);
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok;
}

static bool derive_protection(enum quic_version version,
                              const uint8_t *dcid, size_t dcid_len,
                              struct protection *out) {
    const uint8_t *salt = version == QUIC_V1 ? quic_v1_salt : quic_v2_salt;
    const uint8_t *key_label = version == QUIC_V1 ? key_v1_label : key_v2_label;
    size_t key_label_len = version == QUIC_V1 ? sizeof(key_v1_label) : sizeof(key_v2_label);
    const uint8_t *iv_label = version == QUIC_V1 ? iv_v1_label : iv_v2_label;
    size_t iv_label_len = version == QUIC_V1 ? sizeof(iv_v1_label) : sizeof(iv_v2_label);
    const uint8_t *hp_label = version == QUIC_V1 ? hp_v1_label : hp_v2_label;
    size_t hp_label_len = version == QUIC_V1 ? sizeof(hp_v1_label) : sizeof(hp_v2_label);

    uint8_t initial_secret[32], client_secret[32];
    bool ok = hkdf_extract(salt, 20U, dcid, dcid_len, initial_secret) &&
              hkdf_expand(initial_secret, client_in_label, sizeof(client_in_label),
                          client_secret, sizeof(client_secret)) &&
              hkdf_expand(client_secret, key_label, key_label_len, out->key, sizeof(out->key)) &&
              hkdf_expand(client_secret, iv_label, iv_label_len, out->iv, sizeof(out->iv)) &&
              hkdf_expand(client_secret, hp_label, hp_label_len, out->hp, sizeof(out->hp));
    OPENSSL_cleanse(initial_secret, sizeof(initial_secret));
    OPENSSL_cleanse(client_secret, sizeof(client_secret));
    return ok;
}

static bool aes_ecb_mask(const uint8_t key[16], const uint8_t sample[16],
                         uint8_t mask[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;
    int out_len = 0, final_len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, mask, &out_len, sample, 16) == 1 &&
              EVP_EncryptFinal_ex(ctx, mask + out_len, &final_len) == 1 &&
              out_len + final_len == 16;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static uint64_t reconstruct_pn(const uint8_t *pn, size_t pn_len,
                               bool have_largest, uint64_t largest) {
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; i++) truncated = (truncated << 8) | pn[i];
    if (!have_largest) return truncated;
    unsigned bits = (unsigned)(pn_len * 8U);
    uint64_t window = UINT64_C(1) << bits;
    uint64_t half = window / 2U;
    uint64_t expected = largest == UINT64_MAX ? UINT64_MAX : largest + 1U;
    uint64_t candidate = (expected & ~(window - 1U)) | truncated;
    if (candidate <= UINT64_MAX - half && candidate + half <= expected) {
        return candidate <= UINT64_MAX - window ? candidate + window : candidate;
    }
    if (candidate > expected && candidate - expected > half && candidate >= window) {
        return candidate - window;
    }
    return candidate;
}

static bool aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            uint8_t **plaintext, size_t *plaintext_len) {
    if (ciphertext_len < 16U || aad_len > INT_MAX || ciphertext_len > INT_MAX) return false;
    size_t body_len = ciphertext_len - 16U;
    uint8_t *out = malloc(body_len == 0 ? 1U : body_len);
    if (out == NULL) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) { free(out); return false; }
    int n = 0, total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;
    if (ok && aad_len != 0) ok = EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_len) == 1;
    if (ok && body_len != 0) {
        ok = EVP_DecryptUpdate(ctx, out, &n, ciphertext, (int)body_len) == 1;
        total = n;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                      (void *)(ciphertext + body_len)) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, out + total, &n) == 1;
    if (ok) total += n;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok || total < 0 || (size_t)total != body_len) {
        OPENSSL_cleanse(out, body_len);
        free(out);
        return false;
    }
    *plaintext = out;
    *plaintext_len = body_len;
    return true;
}

static bool unprotect(const uint8_t *packet, size_t packet_len,
                      size_t pn_offset, size_t protected_len,
                      const struct protection *protection,
                      bool have_largest, uint64_t largest,
                      uint8_t **payload, size_t *payload_len,
                      uint64_t *packet_number,
                      struct vane_error *err) {
    if (pn_offset > packet_len || packet_len - pn_offset < 20U) {
        vane_error_set(err, "QUIC packet is too short for header protection sample");
        return false;
    }
    uint8_t mask[16];
    if (!aes_ecb_mask(protection->hp, packet + pn_offset + 4U, mask)) {
        vane_error_set(err, "QUIC header protection failed");
        return false;
    }
    uint8_t first = packet[0] ^ (mask[0] & 0x0fU);
    size_t pn_len = (first & 0x03U) + 1U;
    if (protected_len < pn_len || pn_offset > packet_len - pn_len) {
        vane_error_set(err, "invalid QUIC packet number length");
        return false;
    }
    size_t encrypted_len = protected_len - pn_len;
    size_t encrypted_offset = pn_offset + pn_len;
    if (encrypted_offset > packet_len || encrypted_len > packet_len - encrypted_offset) {
        vane_error_set(err, "truncated QUIC encrypted payload");
        return false;
    }
    uint8_t pn[4] = {0};
    for (size_t i = 0; i < pn_len; i++) pn[i] = packet[pn_offset + i] ^ mask[i + 1U];
    uint64_t pn_value = reconstruct_pn(pn, pn_len, have_largest, largest);
    uint8_t *aad = malloc(encrypted_offset);
    if (aad == NULL) { vane_error_set(err, "out of memory"); return false; }
    memcpy(aad, packet, encrypted_offset);
    aad[0] = first;
    memcpy(aad + pn_offset, pn, pn_len);
    uint8_t nonce[12];
    memcpy(nonce, protection->iv, sizeof(nonce));
    uint8_t pn_be[8];
    for (size_t i = 0; i < 8U; i++) pn_be[7U - i] = (uint8_t)(pn_value >> (i * 8U));
    for (size_t i = 0; i < 8U; i++) nonce[4U + i] ^= pn_be[i];
    bool ok = aes_gcm_decrypt(protection->key, nonce, aad, encrypted_offset,
                              packet + encrypted_offset, encrypted_len,
                              payload, payload_len);
    free(aad);
    if (!ok) {
        vane_error_set(err, "failed to decrypt QUIC Initial");
        return false;
    }
    *packet_number = pn_value;
    return true;
}

static void free_packets(struct initial_packet *packets, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (packets[i].payload != NULL) {
            OPENSSL_cleanse(packets[i].payload, packets[i].payload_len);
            free(packets[i].payload);
        }
    }
    free(packets);
}

static bool append_packet(struct initial_packet **packets, size_t *count,
                          size_t *capacity, struct initial_packet packet,
                          struct vane_error *err) {
    if (*count == *capacity) {
        size_t new_capacity = *capacity == 0 ? 4U : *capacity * 2U;
        if (new_capacity > 64U) {
            vane_error_set(err, "too many coalesced QUIC Initial packets");
            return false;
        }
        struct initial_packet *p = realloc(*packets, new_capacity * sizeof(*p));
        if (p == NULL) { vane_error_set(err, "out of memory"); return false; }
        *packets = p;
        *capacity = new_capacity;
    }
    (*packets)[(*count)++] = packet;
    return true;
}

static bool protection_cache_refresh(struct protection_cache *cache,
                                     enum quic_version version,
                                     const uint8_t *dcid, size_t dcid_len,
                                     struct vane_error *err) {
    bool refresh = !cache->valid || cache->version != version ||
                   cache->dcid_len != dcid_len ||
                   memcmp(cache->dcid, dcid, dcid_len) != 0;
    if (!refresh) return true;

    OPENSSL_cleanse(&cache->keys, sizeof(cache->keys));
    OPENSSL_cleanse(cache->dcid, sizeof(cache->dcid));
    cache->valid = false;
    if (!derive_protection(version, dcid, dcid_len, &cache->keys)) {
        vane_error_set(err, "failed to derive QUIC Initial keys");
        return false;
    }
    cache->version = version;
    cache->dcid_len = dcid_len;
    memcpy(cache->dcid, dcid, dcid_len);
    cache->valid = true;
    return true;
}

static void protection_cache_cleanse(struct protection_cache *cache) {
    OPENSSL_cleanse(cache, sizeof(*cache));
}

static bool collect_datagram(const uint8_t *data, size_t len,
                             struct initial_packet **packets, size_t *count,
                             size_t *capacity, bool *have_largest,
                             uint64_t *largest,
                             struct protection_cache *key_cache,
                             const struct vane_datagram_view *key_dcid,
                             struct vane_error *err) {
    size_t pos = 0;
    bool ok = false;

    while (pos < len) {
        pos += find_initial(data + pos, len - pos);
        if (pos == len) break;
        size_t packet_start = pos++;
        enum quic_version version;
        if (!parse_version(data + pos, &version)) break;
        pos += 4U;
        size_t dcid_len, scid_len;
        const uint8_t *dcid = read_cid(data, len, &pos, &dcid_len);
        if (dcid == NULL) {
            vane_error_set(err, "invalid QUIC DCID");
            goto done;
        }
        const uint8_t *scid = read_cid(data, len, &pos, &scid_len);
        if (scid == NULL) {
            vane_error_set(err, "invalid QUIC SCID");
            goto done;
        }
        size_t token_len = 0;
        if (!read_varint(data, len, &pos, &token_len) || token_len > len - pos) {
            vane_error_set(err, "truncated QUIC token");
            goto done;
        }
        const uint8_t *token = data + pos;
        pos += token_len;
        size_t protected_len = 0;
        if (!read_varint(data, len, &pos, &protected_len) || protected_len > len - pos) {
            vane_error_set(err, "truncated QUIC protected payload");
            goto done;
        }
        size_t packet_end = pos + protected_len;
        size_t pn_offset = pos - packet_start;
        if (!protection_cache_refresh(key_cache, version,
                                        key_dcid != NULL ? key_dcid->data : dcid,
                                        key_dcid != NULL ? key_dcid->len : dcid_len,
                                        err))
            goto done;
        struct initial_packet packet = {
            .version = version, .dcid = dcid, .dcid_len = dcid_len,
            .scid = scid, .scid_len = scid_len,
            .token = token, .token_len = token_len,
        };
        uint64_t pn = 0;
        if (!unprotect(data + packet_start, packet_end - packet_start,
                       pn_offset, protected_len, &key_cache->keys,
                       *have_largest, *largest,
                       &packet.payload, &packet.payload_len, &pn, err)) goto done;
        if (!*have_largest || pn > *largest) *largest = pn;
        *have_largest = true;
        if (!append_packet(packets, count, capacity, packet, err)) {
            OPENSSL_cleanse(packet.payload, packet.payload_len);
            free(packet.payload);
            goto done;
        }
        pos = packet_end;
    }
    ok = true;
done:
    return ok;
}

static bool check_client_initial_size(size_t len, struct vane_error *err) {
    if (len >= VANE_QUIC_MIN_INITIAL_DATAGRAM_SIZE) return true;
    vane_error_set(err, "QUIC Initial datagram is smaller than 1200 bytes");
    return false;
}

static bool same_context(const struct initial_packet *packets, size_t count) {
    if (count == 0) return false;
    const struct initial_packet *a = &packets[0];
    for (size_t i = 1; i < count; i++) {
        const struct initial_packet *b = &packets[i];
        if (a->version != b->version || a->dcid_len != b->dcid_len ||
            a->scid_len != b->scid_len || a->token_len != b->token_len ||
            memcmp(a->dcid, b->dcid, a->dcid_len) != 0 ||
            memcmp(a->scid, b->scid, a->scid_len) != 0 ||
            memcmp(a->token, b->token, a->token_len) != 0) return false;
    }
    return true;
}

static bool skip_ack(const uint8_t *buf, size_t len, size_t *pos, bool ecn) {
    size_t ranges = 0, ignored = 0;
    if (!read_varint(buf, len, pos, &ignored) || !read_varint(buf, len, pos, &ignored) ||
        !read_varint(buf, len, pos, &ranges) || !read_varint(buf, len, pos, &ignored)) return false;
    if (ranges > 1024U) return false;
    for (size_t i = 0; i < ranges; i++) {
        if (!read_varint(buf, len, pos, &ignored) || !read_varint(buf, len, pos, &ignored)) return false;
    }
    if (ecn) {
        if (!read_varint(buf, len, pos, &ignored) || !read_varint(buf, len, pos, &ignored) ||
            !read_varint(buf, len, pos, &ignored)) return false;
    }
    return true;
}

static bool append_frame(struct crypto_frame **frames, size_t *count,
                         size_t *capacity, struct crypto_frame frame,
                         struct vane_error *err) {
    if (*count == *capacity) {
        size_t new_capacity = *capacity == 0 ? 8U : *capacity * 2U;
        if (new_capacity > 1024U) { vane_error_set(err, "too many QUIC CRYPTO frames"); return false; }
        struct crypto_frame *p = realloc(*frames, new_capacity * sizeof(*p));
        if (p == NULL) { vane_error_set(err, "out of memory"); return false; }
        *frames = p;
        *capacity = new_capacity;
    }
    (*frames)[(*count)++] = frame;
    return true;
}

static bool extract_frames(const uint8_t *payload, size_t len,
                           struct crypto_frame **frames, size_t *count,
                           size_t *capacity, struct vane_error *err) {
    size_t pos = 0;
    while (pos < len) {
        uint8_t type = payload[pos++];
        if (type == 0x00U || type == 0x01U) continue;
        if (type == 0x02U || type == 0x03U) {
            if (!skip_ack(payload, len, &pos, type == 0x03U)) {
                vane_error_set(err, "truncated QUIC ACK frame");
                return false;
            }
            continue;
        }
        if (type == 0x06U) {
            /* A control-only check rejects CRYPTO without collecting it. */
            if (frames == NULL) return false;
            size_t offset = 0, data_len = 0;
            if (!read_varint(payload, len, &pos, &offset) ||
                !read_varint(payload, len, &pos, &data_len) || data_len > len - pos) {
                vane_error_set(err, "truncated QUIC CRYPTO frame");
                return false;
            }
            if (offset > VANE_TLS_HANDSHAKE_MAX_SIZE ||
                data_len > VANE_TLS_HANDSHAKE_MAX_SIZE - offset) {
                vane_error_set(err, "QUIC CRYPTO frame exceeds probe limit");
                return false;
            }
            if (!append_frame(frames, count, capacity,
                              (struct crypto_frame){offset, payload + pos, data_len}, err)) return false;
            pos += data_len;
            continue;
        }
        if (type == 0x1cU || type == 0x1dU) {
            size_t ignored = 0, reason_len = 0;
            if (!read_varint(payload, len, &pos, &ignored) ||
                (type == 0x1cU && !read_varint(payload, len, &pos, &ignored)) ||
                !read_varint(payload, len, &pos, &reason_len) || reason_len > len - pos) {
                vane_error_set(err, "truncated QUIC CONNECTION_CLOSE frame");
                return false;
            }
            pos += reason_len;
            continue;
        }
        vane_error_set(err, "unsupported QUIC Initial frame type 0x%02x", type);
        return false;
    }
    return true;
}

bool vane_quic_is_initial_control(
    const uint8_t *data, size_t len,
    const struct vane_datagram_view *key_dcid) {
    if (data == NULL || key_dcid == NULL || key_dcid->data == NULL ||
        key_dcid->len > VANE_QUIC_MAX_CID_LEN ||
        !check_client_initial_size(len, NULL))
        return false;
    struct initial_packet *packets = NULL;
    size_t count = 0U, capacity = 0U;
    bool have_largest = false;
    uint64_t largest = 0U;
    struct protection_cache keys = {0};
    bool matched = collect_datagram(data, len, &packets, &count, &capacity,
                                    &have_largest, &largest, &keys,
                                    key_dcid, NULL) &&
                   same_context(packets, count);
    protection_cache_cleanse(&keys);
    for (size_t i = 0U; matched && i < count; i++)
        matched = extract_frames(packets[i].payload, packets[i].payload_len,
                                  NULL, NULL, NULL, NULL);
    free_packets(packets, count);
    return matched;
}

static int frame_compare(const void *a, const void *b) {
    const struct crypto_frame *fa = a, *fb = b;
    if (fa->offset < fb->offset) return -1;
    if (fa->offset > fb->offset) return 1;
    if (fa->len < fb->len) return -1;
    if (fa->len > fb->len) return 1;
    return 0;
}

static enum vane_probe_result reassemble_and_parse(struct crypto_frame *frames,
                                                      size_t count,
                                                      struct vane_client_hello *hello,
                                                      uint8_t **storage, size_t *storage_cap,
                                                      struct vane_error *err) {
    if (count == 0) return VANE_PROBE_NEED_MORE;
    if (count == 1U) {
        /* extract_frames has already checked the offset and length. */
        if (frames[0].offset != 0U) return VANE_PROBE_NEED_MORE;
        return vane_tls_parse_handshake(frames[0].data, frames[0].len, hello, err);
    }
    qsort(frames, count, sizeof(*frames), frame_compare);
    size_t stream_len = 0;
    for (size_t i = 0; i < count; i++) {
        if (frames[i].offset > VANE_TLS_HANDSHAKE_MAX_SIZE ||
            frames[i].len > VANE_TLS_HANDSHAKE_MAX_SIZE - frames[i].offset) {
            vane_error_set(err, "QUIC CRYPTO stream exceeds probe limit");
            return VANE_PROBE_MALFORMED;
        }
        size_t end = frames[i].offset + frames[i].len;
        /* Sparse far-ahead CRYPTO data does not require a large assembly
         * allocation until the gap has actually arrived. */
        if (frames[i].offset <= stream_len && end > stream_len)
            stream_len = end;
    }
    if (stream_len == 0U) return VANE_PROBE_NEED_MORE;
    if (stream_len > *storage_cap) {
        uint8_t *larger = realloc(*storage, stream_len);
        if (larger == NULL) {
            vane_error_set(err, "out of memory");
            return VANE_PROBE_MALFORMED;
        }
        *storage = larger;
        *storage_cap = stream_len;
    }
    uint8_t *stream = *storage;
    size_t written = 0;
    enum vane_probe_result result = VANE_PROBE_NEED_MORE;
    for (size_t i = 0; i < count; i++) {
        const struct crypto_frame *f = &frames[i];
        if (f->offset > written) break;
        if (f->offset < written) {
            size_t overlap = written - f->offset;
            size_t compare_len = VANE_MIN(overlap, f->len);
            if (memcmp(stream + f->offset, f->data, compare_len) != 0) {
                vane_error_set(err, "conflicting overlapping QUIC CRYPTO frames");
                result = VANE_PROBE_MALFORMED;
                goto done;
            }
            if (overlap >= f->len) continue;
            memcpy(stream + written, f->data + overlap, f->len - overlap);
            written += f->len - overlap;
        } else {
            memcpy(stream + written, f->data, f->len);
            written += f->len;
        }
    }
    result = vane_tls_parse_handshake(stream, written, hello, err);
done:
    return result;
}

struct probe_payload {
    uint8_t *data;
    size_t len;
};

struct vane_quic_probe_state {
    struct protection_cache key_cache;
    bool have_largest;
    uint64_t largest;
    bool have_context;
    enum quic_version version;
    uint8_t dcid[VANE_QUIC_MAX_CID_LEN];
    size_t dcid_len;
    uint8_t scid[VANE_QUIC_MAX_CID_LEN];
    size_t scid_len;
    uint8_t *token;
    size_t token_len;
    struct probe_payload *payloads;
    size_t payload_count;
    size_t payload_capacity;
    struct crypto_frame *frames;
    size_t frame_count;
    size_t frame_capacity;
    uint8_t *stream;
    size_t stream_capacity;
};

struct vane_quic_probe_state *vane_quic_probe_state_new(void) {
    return calloc(1U, sizeof(struct vane_quic_probe_state));
}

void vane_quic_probe_state_free(struct vane_quic_probe_state *state) {
    if (state == NULL) return;
    protection_cache_cleanse(&state->key_cache);
    if (state->token != NULL) {
        OPENSSL_cleanse(state->token, state->token_len);
        free(state->token);
    }
    if (state->payloads != NULL) {
        for (size_t i = 0U; i < state->payload_count; i++) {
            if (state->payloads[i].data != NULL) {
                OPENSSL_cleanse(state->payloads[i].data,
                                state->payloads[i].len);
                free(state->payloads[i].data);
            }
        }
        free(state->payloads);
    }
    free(state->frames);
    if (state->stream != NULL) {
        OPENSSL_cleanse(state->stream, state->stream_capacity);
        free(state->stream);
    }
    OPENSSL_cleanse(state, sizeof(*state));
    free(state);
}

static bool streaming_context_accept(struct vane_quic_probe_state *state,
                                     const struct initial_packet *packet,
                                     struct vane_error *err) {
    if (!state->have_context) {
        state->version = packet->version;
        state->dcid_len = packet->dcid_len;
        state->scid_len = packet->scid_len;
        memcpy(state->dcid, packet->dcid, packet->dcid_len);
        memcpy(state->scid, packet->scid, packet->scid_len);
        if (packet->token_len != 0U) {
            state->token = malloc(packet->token_len);
            if (state->token == NULL) {
                vane_error_set(err, "out of memory");
                return false;
            }
            memcpy(state->token, packet->token, packet->token_len);
        }
        state->token_len = packet->token_len;
        state->have_context = true;
        return true;
    }
    if (state->version != packet->version ||
        state->dcid_len != packet->dcid_len ||
        state->scid_len != packet->scid_len ||
        state->token_len != packet->token_len ||
        memcmp(state->dcid, packet->dcid, state->dcid_len) != 0 ||
        memcmp(state->scid, packet->scid, state->scid_len) != 0 ||
        (state->token_len != 0U &&
         memcmp(state->token, packet->token, state->token_len) != 0)) {
        vane_error_set(err, "QUIC Initial packet context changed during probe");
        return false;
    }
    return true;
}

static bool streaming_append_payload(struct vane_quic_probe_state *state,
                                     uint8_t *payload, size_t payload_len,
                                     struct vane_error *err) {
    if (state->payload_count == state->payload_capacity) {
        size_t new_capacity = state->payload_capacity == 0U
            ? 4U : state->payload_capacity * 2U;
        if (new_capacity > 64U) {
            vane_error_set(err, "too many QUIC Initial packets during probe");
            return false;
        }
        struct probe_payload *new_payloads =
            realloc(state->payloads, new_capacity * sizeof(*new_payloads));
        if (new_payloads == NULL) {
            vane_error_set(err, "out of memory");
            return false;
        }
        state->payloads = new_payloads;
        state->payload_capacity = new_capacity;
    }
    state->payloads[state->payload_count++] =
        (struct probe_payload){.data = payload, .len = payload_len};
    return true;
}

enum vane_probe_result
vane_quic_probe_feed(struct vane_quic_probe_state *state,
                       const uint8_t *datagram, size_t datagram_len,
                       struct vane_client_hello *hello,
                       struct vane_error *err) {
    if (state == NULL || datagram == NULL || hello == NULL)
        return VANE_PROBE_NOT_PROTOCOL;
    memset(hello, 0, sizeof(*hello));
    if (!vane_quic_looks_like_initial(datagram, datagram_len))
        return state->have_context ? VANE_PROBE_NEED_MORE
                                   : VANE_PROBE_NOT_PROTOCOL;
    if (!check_client_initial_size(datagram_len, err))
        return VANE_PROBE_MALFORMED;

    struct initial_packet *fresh = NULL;
    size_t fresh_count = 0U, fresh_capacity = 0U;
    if (!collect_datagram(datagram, datagram_len,
                          &fresh, &fresh_count, &fresh_capacity,
                          &state->have_largest, &state->largest,
                          &state->key_cache, NULL, err)) {
        free_packets(fresh, fresh_count);
        return VANE_PROBE_MALFORMED;
    }
    if (fresh_count == 0U) {
        free(fresh);
        return state->have_context ? VANE_PROBE_NEED_MORE
                                   : VANE_PROBE_NOT_PROTOCOL;
    }

    for (size_t i = 0U; i < fresh_count; i++) {
        if (!streaming_context_accept(state, &fresh[i], err) ||
            !streaming_append_payload(state, fresh[i].payload,
                                      fresh[i].payload_len, err)) {
            for (size_t j = i; j < fresh_count; j++) {
                if (fresh[j].payload != NULL) {
                    OPENSSL_cleanse(fresh[j].payload, fresh[j].payload_len);
                    free(fresh[j].payload);
                }
            }
            free(fresh);
            return VANE_PROBE_MALFORMED;
        }
        fresh[i].payload = NULL;
        fresh[i].payload_len = 0U;
    }
    /* Frame data points into the retained decrypted payloads. Extract only
     * the newly received packets; previous frames remain valid in state. */
    free(fresh);
    for (size_t i = state->payload_count - fresh_count;
         i < state->payload_count; i++) {
        if (!extract_frames(state->payloads[i].data, state->payloads[i].len,
                            &state->frames, &state->frame_count,
                            &state->frame_capacity, err))
            return VANE_PROBE_MALFORMED;
    }
    return reassemble_and_parse(state->frames, state->frame_count, hello,
                                &state->stream, &state->stream_capacity, err);
}

enum vane_probe_result
vane_quic_parse_client_hello(const struct vane_datagram_view *datagrams,
                               size_t datagram_count,
                               struct vane_client_hello *hello,
                               struct vane_error *err) {
    if (datagrams == NULL || datagram_count == 0 || hello == NULL) return VANE_PROBE_NOT_PROTOCOL;
    memset(hello, 0, sizeof(*hello));
    struct initial_packet *packets = NULL;
    size_t packet_count = 0, packet_capacity = 0;
    bool saw_candidate = false, have_largest = false;
    uint64_t largest = 0;
    struct protection_cache key_cache = {0};
    for (size_t i = 0; i < datagram_count; i++) {
        if (!vane_quic_looks_like_initial(datagrams[i].data, datagrams[i].len)) continue;
        saw_candidate = true;
        if (!check_client_initial_size(datagrams[i].len, err) ||
            !collect_datagram(datagrams[i].data, datagrams[i].len,
                              &packets, &packet_count, &packet_capacity,
                              &have_largest, &largest, &key_cache, NULL, err)) {
            protection_cache_cleanse(&key_cache);
            free_packets(packets, packet_count);
            return VANE_PROBE_MALFORMED;
        }
    }
    protection_cache_cleanse(&key_cache);
    if (!saw_candidate || packet_count == 0) {
        free_packets(packets, packet_count);
        return VANE_PROBE_NOT_PROTOCOL;
    }
    if (!same_context(packets, packet_count)) {
        vane_error_set(err, "QUIC Initial packet context changed during probe");
        free_packets(packets, packet_count);
        return VANE_PROBE_MALFORMED;
    }
    struct crypto_frame *frames = NULL;
    size_t frame_count = 0, frame_capacity = 0;
    bool ok = true;
    for (size_t i = 0; i < packet_count; i++) {
        if (!extract_frames(packets[i].payload, packets[i].payload_len,
                            &frames, &frame_count, &frame_capacity, err)) {
            ok = false;
            break;
        }
    }
    uint8_t *stream = NULL;
    size_t stream_capacity = 0U;
    enum vane_probe_result result = ok
        ? reassemble_and_parse(frames, frame_count, hello,
                                &stream, &stream_capacity, err)
        : VANE_PROBE_MALFORMED;
    if (stream != NULL) {
        OPENSSL_cleanse(stream, stream_capacity);
        free(stream);
    }
    free(frames);
    free_packets(packets, packet_count);
    return result;
}
