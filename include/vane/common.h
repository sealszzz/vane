#ifndef VANE_COMMON_H
#define VANE_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VANE_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define VANE_MIN(a, b) ((a) < (b) ? (a) : (b))
#define VANE_MAX(a, b) ((a) > (b) ? (a) : (b))
#define VANE_UNUSED(x) ((void)(x))

#define VANE_TLS_HANDSHAKE_MAX_SIZE (64U * 1024U)
#define VANE_MAX_SNI_LEN 253U
#define VANE_MAX_ERROR_LEN 512U
#define VANE_MAX_LISTENERS 64U
#define VANE_MAX_TARGETS 4096U
#define VANE_MAX_WORKERS 256U

struct vane_error {
    char message[VANE_MAX_ERROR_LEN];
};

void vane_error_set(struct vane_error *err, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

uint64_t vane_monotonic_ms(void);
uint64_t vane_random_u64(void);
size_t vane_available_cpu_count(void);

#endif
