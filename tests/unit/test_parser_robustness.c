#include "vane/quic_parser.h"
#include "vane/tls_parser.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint32_t next_random(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

int main(void) {
    uint8_t data[2048];
    uint32_t state = UINT32_C(0x5a17c9e3);
    struct vane_client_hello hello;
    struct vane_error err;

    for (size_t iteration = 0; iteration < 4000U; iteration++) {
        size_t len = (size_t)(next_random(&state) % (sizeof(data) + 1U));
        for (size_t i = 0; i < len; i++) data[i] = (uint8_t)next_random(&state);
        memset(&err, 0, sizeof(err));
        enum vane_probe_result tls =
            vane_tls_parse_records(data, len, &hello, &err);
        assert(tls >= VANE_PROBE_MATCHED && tls <= VANE_PROBE_MALFORMED);

        if (len >= 5U && iteration % 7U == 0U) {
            data[0] = iteration % 14U == 0U ? 0xc0U : 0xd0U;
            if (data[0] == 0xc0U) {
                data[1] = 0x00U; data[2] = 0x00U; data[3] = 0x00U; data[4] = 0x01U;
            } else {
                data[1] = 0x6bU; data[2] = 0x33U; data[3] = 0x43U; data[4] = 0xcfU;
            }
        }
        struct vane_datagram_view view = {.data = data, .len = len};
        memset(&err, 0, sizeof(err));
        enum vane_probe_result quic =
            vane_quic_parse_client_hello(&view, 1U, &hello, &err);
        assert(quic >= VANE_PROBE_MATCHED && quic <= VANE_PROBE_MALFORMED);
    }
    return 0;
}
