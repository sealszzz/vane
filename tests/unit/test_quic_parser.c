#include "vane/quic_parser.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VANE_TEST_FIXTURE_DIR
#define VANE_TEST_FIXTURE_DIR "tests/fixtures"
#endif

static uint8_t *read_fixture(const char *name, size_t *len_out) {
    char path[512];
    int written = snprintf(path, sizeof(path), "%s/%s", VANE_TEST_FIXTURE_DIR, name);
    assert(written > 0 && (size_t)written < sizeof(path));
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0);
    assert(fseek(file, 0, SEEK_SET) == 0);
    uint8_t *data = malloc((size_t)size);
    assert(data != NULL);
    assert(fread(data, 1, (size_t)size, file) == (size_t)size);
    assert(fclose(file) == 0);
    *len_out = (size_t)size;
    return data;
}

static void test_random_and_truncated(void) {
    const uint8_t random[] = "not-quic";
    struct vane_datagram_view view = {random, sizeof(random) - 1U};
    struct vane_client_hello hello;
    struct vane_error err = {0};
    assert(!vane_quic_looks_like_initial(random, sizeof(random) - 1U));
    assert(vane_quic_parse_client_hello(&view, 1, &hello, &err) ==
           VANE_PROBE_NOT_PROTOCOL);
    const uint8_t short_initial[] = {0xc0, 0, 0, 0, 1};
    assert(vane_quic_looks_like_initial(short_initial, sizeof(short_initial)));
    view.data = short_initial;
    view.len = sizeof(short_initial);
    memset(&err, 0, sizeof(err));
    assert(vane_quic_parse_client_hello(&view, 1, &hello, &err) ==
           VANE_PROBE_MALFORMED);

    const uint8_t truncated[] = {0xc0, 0, 0, 0, 1, 8, 1, 2};
    assert(vane_quic_looks_like_initial(truncated, sizeof(truncated)));
    view.data = truncated;
    view.len = sizeof(truncated);
    assert(vane_quic_parse_client_hello(&view, 1, &hello, &err) ==
           VANE_PROBE_MALFORMED);
}

static void test_real_nextquic_initial(void) {
    size_t lengths[2];
    uint8_t *packets[2] = {
        read_fixture("nextquic-v1-initial-1.bin", &lengths[0]),
        read_fixture("nextquic-v1-initial-2.bin", &lengths[1]),
    };
    struct vane_datagram_view views[2] = {
        {packets[0], lengths[0]},
        {packets[1], lengths[1]},
    };
    struct vane_client_hello hello;
    struct vane_error err = {0};
    struct vane_quic_initial_identity identity1;
    struct vane_quic_initial_identity identity2;
    assert(vane_quic_read_initial_identity(packets[0], lengths[0],
                                             &identity1));
    assert(vane_quic_read_initial_identity(packets[1], lengths[1],
                                             &identity2));
    assert(identity1.version == UINT32_C(1));
    assert(identity1.source_connection_id_len > 0U);
    assert(vane_quic_initial_identity_equal(&identity1, &identity2));

    uint8_t *zero_rtt = malloc(lengths[0]);
    assert(zero_rtt != NULL);
    memcpy(zero_rtt, packets[0], lengths[0]);
    zero_rtt[0] = (uint8_t)((zero_rtt[0] & 0x0fU) | 0xd0U);
    struct vane_quic_initial_identity zero_rtt_identity;
    assert(!vane_quic_read_initial_identity(zero_rtt, lengths[0],
                                              &zero_rtt_identity));
    assert(vane_quic_read_long_header_identity(zero_rtt, lengths[0],
                                                 &zero_rtt_identity));
    assert(vane_quic_initial_identity_equal(&identity1,
                                              &zero_rtt_identity));
    free(zero_rtt);

    uint8_t *retry = malloc(lengths[0]);
    assert(retry != NULL);
    memcpy(retry, packets[0], lengths[0]);
    retry[0] = (uint8_t)((retry[0] & 0x0fU) | 0xf0U);
    assert(vane_quic_looks_like_retry(retry, lengths[0]));
    assert(!vane_quic_looks_like_initial(retry, lengths[0]));
    free(retry);

    identity2.source_connection_id[0] ^= 1U;
    assert(!vane_quic_initial_identity_equal(&identity1, &identity2));

    assert(vane_quic_parse_client_hello(views, 1, &hello, &err) ==
           VANE_PROBE_NEED_MORE);
    memset(&err, 0, sizeof(err));
    assert(vane_quic_parse_client_hello(views, 2, &hello, &err) ==
           VANE_PROBE_MATCHED);
    assert(hello.has_sni);
    assert(hello.server_name_len == strlen("localhost"));
    assert(strcmp(hello.server_name, "localhost") == 0);

    struct vane_quic_probe_state *state = vane_quic_probe_state_new();
    assert(state != NULL);
    memset(&err, 0, sizeof(err));
    assert(vane_quic_probe_feed(state, packets[0], lengths[0],
                                  &hello, &err) == VANE_PROBE_NEED_MORE);
    memset(&err, 0, sizeof(err));
    assert(vane_quic_probe_feed(state, packets[1], lengths[1],
                                  &hello, &err) == VANE_PROBE_MATCHED);
    assert(hello.has_sni);
    assert(strcmp(hello.server_name, "localhost") == 0);
    vane_quic_probe_state_free(state);

    uint8_t *corrupt = malloc(lengths[0]);
    assert(corrupt != NULL);
    memcpy(corrupt, packets[0], lengths[0]);
    corrupt[lengths[0] - 1U] ^= 0x80U;
    struct vane_datagram_view corrupt_view = {corrupt, lengths[0]};
    memset(&err, 0, sizeof(err));
    assert(vane_quic_parse_client_hello(&corrupt_view, 1, &hello, &err) ==
           VANE_PROBE_MALFORMED);
    free(corrupt);
    free(packets[0]);
    free(packets[1]);
}

int main(void) {
    test_random_and_truncated();
    test_real_nextquic_initial();
    return 0;
}
