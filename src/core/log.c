#include "vane/log.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static _Atomic int current_level = (int)VANE_LOG_INFO;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void vane_log_set_level(enum vane_log_level level) {
    atomic_store_explicit(&current_level, (int)level, memory_order_relaxed);
}

bool vane_log_enabled(enum vane_log_level level) {
    return (int)level <= atomic_load_explicit(&current_level, memory_order_relaxed);
}

void vane_log(enum vane_log_level level, const char *fmt, ...) {
    if (!vane_log_enabled(level)) return;
    static const char *const names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    unsigned idx = (unsigned)level;
    const char *label = idx < VANE_ARRAY_LEN(names) ? names[idx] : "INFO";
    struct timespec ts = {0};
    struct tm tm = {0};
    char stamp[32] = "1970-01-01T00:00:00";
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0 &&
        gmtime_r(&ts.tv_sec, &tm) != NULL) {
        if (strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm) == 0U)
            stamp[0] = '\0';
    }

    (void)pthread_mutex_lock(&log_lock);
    (void)fprintf(stderr, "%s.%03ldZ %-5s ", stamp, ts.tv_nsec / 1000000L,
                  label);
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
    (void)pthread_mutex_unlock(&log_lock);
}
