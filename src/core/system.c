#include "vane/common.h"

#include <errno.h>
#include <sys/random.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

void vane_error_set(struct vane_error *err, const char *fmt, ...) {
    if (err == NULL) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err->message, sizeof(err->message), fmt, ap);
    va_end(ap);
}

uint64_t vane_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

uint64_t vane_random_u64(void) {
    uint64_t value = 0U;
    unsigned char *out = (unsigned char *)&value;
    size_t offset = 0U;
    while (offset < sizeof(value)) {
        ssize_t n = getrandom(out + offset, sizeof(value) - offset, 0);
        if (n > 0) { offset += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (offset == sizeof(value)) return value;
    struct timespec realtime = {0};
    (void)clock_gettime(CLOCK_REALTIME, &realtime);
    value ^= vane_monotonic_ms();
    value ^= (uint64_t)realtime.tv_sec << 32;
    value ^= (uint64_t)realtime.tv_nsec;
    value ^= (uint64_t)(uintptr_t)&value;
    value ^= (uint64_t)getpid() << 16;
    value ^= value >> 30; value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27; value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

size_t vane_available_cpu_count(void) {
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    if (sched_getaffinity(0, sizeof(affinity), &affinity) == 0) {
        int count = CPU_COUNT(&affinity);
        if (count > 0) {
            size_t result = (size_t)count;
            return result > VANE_MAX_WORKERS ? VANE_MAX_WORKERS : result;
        }
    }

    long online = sysconf(_SC_NPROCESSORS_ONLN);
    if (online <= 0) {
        return 1U;
    }
    size_t result = (size_t)online;
    return result > VANE_MAX_WORKERS ? VANE_MAX_WORKERS : result;
}
