#include "vane/log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static enum vane_log_level current_level = VANE_LOG_INFO;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void vane_log_set_level(enum vane_log_level level) {
    current_level = level;
}

bool vane_log_enabled(enum vane_log_level level) {
    return level <= current_level;
}

void vane_log(enum vane_log_level level, const char *fmt, ...) {
    if (!vane_log_enabled(level)) return;
    static const char *const names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    (void)gmtime_r(&ts.tv_sec, &tm);
    char stamp[32];
    (void)strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);

    (void)pthread_mutex_lock(&log_lock);
    (void)fprintf(stderr, "%s.%03ldZ %-5s ", stamp, ts.tv_nsec / 1000000L,
                  names[(unsigned)level]);
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
    (void)pthread_mutex_unlock(&log_lock);
}
