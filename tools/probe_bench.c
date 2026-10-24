/* Diagnostic microbenchmark; does not represent end-to-end QUIC throughput. */
#include "vane/quic_parser.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double cpu_seconds(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    for (size_t count = 2U; count <= 8U; count += 6U) {
        struct vane_datagram_view views[8];
        uint8_t data[8][4096];
        for (size_t i = 0U; i < count; i++) {
            char path[1024];
            if (count == 2U)
                (void)snprintf(path, sizeof(path), "%s/nextquic-v1-initial-%zu.bin", argv[1], i + 1U);
            else
                (void)snprintf(path, sizeof(path), "%s/crypto-fragment-%zu.bin", argv[1], i);
            FILE *file = fopen(path, "rb");
            assert(file != NULL);
            size_t len = fread(data[i], 1U, sizeof(data[i]), file);
            assert(len > 0U && feof(file));
            assert(fclose(file) == 0);
            views[i] = (struct vane_datagram_view){data[i], len};
        }
        const size_t iterations = 5000U;
        double start = cpu_seconds();
        for (size_t iteration = 0U; iteration < iterations; iteration++) {
            struct vane_quic_probe_state *state = vane_quic_probe_state_new();
            assert(state != NULL);
            struct vane_client_hello hello;
            struct vane_error err = {0};
            for (size_t i = 0U; i < count; i++) {
                enum vane_probe_result result = vane_quic_probe_feed(
                    state, views[i].data, views[i].len, &hello, &err);
                assert(result == (i + 1U == count ? VANE_PROBE_MATCHED : VANE_PROBE_NEED_MORE));
            }
            assert(strcmp(hello.server_name, "localhost") == 0);
            vane_quic_probe_state_free(state);
        }
        printf("packets=%zu iterations=%zu cpu_us_per_probe=%.3f\n", count,
               iterations, (cpu_seconds() - start) * 1e6 / (double)iterations);
    }
    return 0;
}
