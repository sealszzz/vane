#ifndef VANE_LOG_H
#define VANE_LOG_H

#include "vane/config.h"

void vane_log_set_level(enum vane_log_level level);
bool vane_log_enabled(enum vane_log_level level);
void vane_log(enum vane_log_level level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define VANE_LOG_IF(level, ...) \
    do { \
        if (vane_log_enabled((level))) \
            vane_log((level), __VA_ARGS__); \
    } while (0)

#define LOG_ERROR(...) VANE_LOG_IF(VANE_LOG_ERROR, __VA_ARGS__)
#define LOG_WARN(...)  VANE_LOG_IF(VANE_LOG_WARN, __VA_ARGS__)
#define LOG_INFO(...)  VANE_LOG_IF(VANE_LOG_INFO, __VA_ARGS__)
#define LOG_DEBUG(...) VANE_LOG_IF(VANE_LOG_DEBUG, __VA_ARGS__)
#define LOG_TRACE(...) VANE_LOG_IF(VANE_LOG_TRACE, __VA_ARGS__)

#endif
