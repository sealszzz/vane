#include "vane/runtime.h"

#include "vane/log.h"
#include "vane/route.h"
#include "workers.h"

#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif

#define VANE_WORKER_STACK_BYTES (1024U * 1024U)


void vane_worker_report_start(struct vane_worker_startup *startup, bool success) {
    (void)pthread_mutex_lock(&startup->mutex);
    startup->reported++;
    if (!success) {
        startup->failed = true;
        atomic_store_explicit(&startup->stop, true, memory_order_release);
    }
    (void)pthread_cond_broadcast(&startup->cond);
    (void)pthread_mutex_unlock(&startup->mutex);
}

void vane_worker_request_stop(struct vane_worker_startup *startup) {
    (void)pthread_mutex_lock(&startup->mutex);
    startup->failed = true;
    atomic_store_explicit(&startup->stop, true, memory_order_release);
    (void)pthread_cond_broadcast(&startup->cond);
    (void)pthread_mutex_unlock(&startup->mutex);
}

bool vane_worker_should_stop(const struct vane_worker_startup *startup) {
    return atomic_load_explicit(&startup->stop, memory_order_acquire);
}

struct thread_record {
    pthread_t thread;
    struct vane_worker_args args;
};

static size_t shard_share(size_t total, size_t shards, size_t index) {
    return total / shards + (index < total % shards ? 1U : 0U);
}

static void destroy_route_tables(struct vane_route_table **routes,
                                 size_t listener_count) {
    if (routes == NULL) return;
    for (size_t i = 0; i < listener_count; i++)
        vane_route_table_destroy(routes[i]);
    free(routes);
}

static bool notify_ready(struct vane_error *err) {
    const char *path = getenv("NOTIFY_SOCKET");
    if (path == NULL || path[0] == '\0') return true;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t len = strlen(path);
    if ((path[0] != '/' && path[0] != '@') ||
        len >= sizeof(address.sun_path)) {
        vane_error_set(err, "invalid NOTIFY_SOCKET address");
        return false;
    }
    memcpy(address.sun_path, path, len + 1U);
    size_t address_len = offsetof(struct sockaddr_un, sun_path) + len + 1U;
    if (path[0] == '@') {
        address.sun_path[0] = '\0';
        address_len--;
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        vane_error_set(err, "readiness socket: %s", strerror(errno));
        return false;
    }
    static const char message[] = "READY=1";
    ssize_t sent;
    do {
        sent = sendto(fd, message, sizeof(message) - 1U, MSG_NOSIGNAL,
                      (const struct sockaddr *)&address, (socklen_t)address_len);
    } while (sent < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (sent != (ssize_t)(sizeof(message) - 1U)) {
        vane_error_set(err, "readiness notification: %s",
                         strerror(sent < 0 ? saved : EIO));
        return false;
    }
    return true;
}

bool vane_runtime_run(const struct vane_config *config,
                        struct vane_error *err) {
#ifdef __GLIBC__
    (void)mallopt(M_ARENA_MAX, 2);
#endif
    struct vane_route_table **routes =
        calloc(config->listener_count, sizeof(*routes));
    if (routes == NULL) {
        vane_error_set(err, "out of memory");
        return false;
    }
    for (size_t i = 0; i < config->listener_count; i++) {
        if (!vane_route_table_build(&config->listeners[i], &routes[i], err)) {
            destroy_route_tables(routes, config->listener_count);
            return false;
        }
    }

    if (config->listener_count > SIZE_MAX / config->runtime.workers) {
        vane_error_set(err, "worker count overflow");
        destroy_route_tables(routes, config->listener_count);
        return false;
    }
    size_t total = config->listener_count * config->runtime.workers;
    struct thread_record *threads = calloc(total, sizeof(*threads));
    if (threads == NULL) {
        vane_error_set(err, "out of memory");
        destroy_route_tables(routes, config->listener_count);
        return false;
    }

    size_t tcp_listeners = 0U, udp_listeners = 0U;
    for (size_t i = 0; i < config->listener_count; i++) {
        if (config->listeners[i].transport == VANE_TRANSPORT_TCP) tcp_listeners++;
        else udp_listeners++;
    }
    size_t tcp_shards = tcp_listeners * config->runtime.workers;
    size_t udp_shards = udp_listeners * config->runtime.workers;
    size_t tcp_shard_index = 0U, udp_shard_index = 0U;

    struct vane_worker_startup startup;
    memset(&startup, 0, sizeof(startup));
    int mutex_rc = pthread_mutex_init(&startup.mutex, NULL);
    if (mutex_rc != 0) {
        vane_error_set(err, "pthread_mutex_init: %s", strerror(mutex_rc));
        free(threads);
        destroy_route_tables(routes, config->listener_count);
        return false;
    }
    int cond_rc = pthread_cond_init(&startup.cond, NULL);
    if (cond_rc != 0) {
        vane_error_set(err, "pthread_cond_init: %s", strerror(cond_rc));
        (void)pthread_mutex_destroy(&startup.mutex);
        free(threads);
        destroy_route_tables(routes, config->listener_count);
        return false;
    }
    atomic_init(&startup.stop, false);

    sigset_t stop_signals;
    sigset_t old_signal_mask;
    (void)sigemptyset(&stop_signals);
    (void)sigaddset(&stop_signals, SIGINT);
    (void)sigaddset(&stop_signals, SIGTERM);
    int mask_rc = pthread_sigmask(SIG_BLOCK, &stop_signals, &old_signal_mask);
    if (mask_rc != 0) {
        vane_error_set(err, "pthread_sigmask: %s", strerror(mask_rc));
        (void)pthread_cond_destroy(&startup.cond);
        (void)pthread_mutex_destroy(&startup.mutex);
        free(threads);
        destroy_route_tables(routes, config->listener_count);
        return false;
    }
    bool signal_mask_live = true;

    pthread_attr_t thread_attr;
    bool thread_attr_live = false;
    int attr_rc = pthread_attr_init(&thread_attr);
    if (attr_rc != 0) {
        vane_error_set(err, "pthread_attr_init: %s", strerror(attr_rc));
        (void)pthread_sigmask(SIG_SETMASK, &old_signal_mask, NULL);
        (void)pthread_cond_destroy(&startup.cond);
        (void)pthread_mutex_destroy(&startup.mutex);
        free(threads);
        destroy_route_tables(routes, config->listener_count);
        return false;
    }
    thread_attr_live = true;
    size_t stack_size = VANE_WORKER_STACK_BYTES;
    if (stack_size < (size_t)PTHREAD_STACK_MIN) stack_size = (size_t)PTHREAD_STACK_MIN;
    attr_rc = pthread_attr_setstacksize(&thread_attr, stack_size);
    if (attr_rc != 0) {
        vane_error_set(err, "pthread_attr_setstacksize: %s", strerror(attr_rc));
        (void)pthread_attr_destroy(&thread_attr);
        (void)pthread_sigmask(SIG_SETMASK, &old_signal_mask, NULL);
        (void)pthread_cond_destroy(&startup.cond);
        (void)pthread_mutex_destroy(&startup.mutex);
        free(threads);
        destroy_route_tables(routes, config->listener_count);
        return false;
    }

    size_t started = 0;
    for (size_t i = 0; i < config->listener_count; i++) {
        for (size_t w = 0; w < config->runtime.workers; w++) {
            struct thread_record *record = &threads[started];
            record->args.worker_index = w;
            record->args.listener = &config->listeners[i];
            record->args.runtime = &config->runtime;
            record->args.routes = routes[i];
            record->args.startup = &startup;
            if (config->listeners[i].transport == VANE_TRANSPORT_TCP) {
                record->args.tcp_connection_limit = shard_share(
                    config->runtime.tcp_max_connections, tcp_shards, tcp_shard_index);
                record->args.tcp_connecting_limit = shard_share(
                    config->runtime.tcp_max_connecting, tcp_shards, tcp_shard_index);
                tcp_shard_index++;
            } else {
                record->args.udp_flow_base_limit = shard_share(
                    config->runtime.udp_flow_capacity, udp_shards, udp_shard_index);
                record->args.udp_pending_limit = shard_share(
                    config->runtime.udp_max_pending_probes, udp_shards, udp_shard_index);
                udp_shard_index++;
            }
            void *(*entry)(void *) = config->listeners[i].transport == VANE_TRANSPORT_TCP
                ? vane_tcp_worker_main : vane_udp_worker_main;
            int rc = pthread_create(&record->thread, &thread_attr, entry, &record->args);
            if (rc != 0) {
                vane_error_set(err, "pthread_create: %s", strerror(rc));
                goto fail;
            }
            started++;
        }
    }

    (void)pthread_attr_destroy(&thread_attr);
    thread_attr_live = false;

    (void)pthread_mutex_lock(&startup.mutex);
    while (startup.reported < started)
        (void)pthread_cond_wait(&startup.cond, &startup.mutex);
    bool startup_failed = startup.failed;
    (void)pthread_mutex_unlock(&startup.mutex);
    if (startup_failed) {
        vane_error_set(err, "one or more workers failed to initialize");
        goto fail;
    }
    if (vane_worker_should_stop(&startup)) {
        vane_error_set(err, "a worker stopped before readiness");
        goto fail;
    }
    if (!notify_ready(err)) goto fail;

    while (!vane_worker_should_stop(&startup)) {
        const struct timespec wait = {.tv_sec = 0, .tv_nsec = 100000000L};
        int signo = sigtimedwait(&stop_signals, NULL, &wait);
        if (signo == SIGINT || signo == SIGTERM) {
            LOG_INFO("received signal %d; stopping workers", signo);
            atomic_store_explicit(&startup.stop, true, memory_order_release);
            break;
        }
        if (signo < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (signo < 0) {
            vane_error_set(err, "sigtimedwait: %s", strerror(errno));
            vane_worker_request_stop(&startup);
            break;
        }
    }

    for (size_t i = 0; i < started; i++)
        (void)pthread_join(threads[i].thread, NULL);
    bool runtime_failed = startup.failed;
    if (signal_mask_live) {
        (void)pthread_sigmask(SIG_SETMASK, &old_signal_mask, NULL);
        signal_mask_live = false;
    }
    (void)pthread_cond_destroy(&startup.cond);
    (void)pthread_mutex_destroy(&startup.mutex);
    free(threads);
    destroy_route_tables(routes, config->listener_count);
    if (runtime_failed) {
        vane_error_set(err, "a worker stopped after a runtime failure");
        return false;
    }
    return true;

fail:
    if (thread_attr_live) (void)pthread_attr_destroy(&thread_attr);
    atomic_store_explicit(&startup.stop, true, memory_order_release);
    for (size_t i = 0; i < started; i++)
        (void)pthread_join(threads[i].thread, NULL);
    if (signal_mask_live) {
        (void)pthread_sigmask(SIG_SETMASK, &old_signal_mask, NULL);
        signal_mask_live = false;
    }
    (void)pthread_cond_destroy(&startup.cond);
    (void)pthread_mutex_destroy(&startup.mutex);
    free(threads);
    destroy_route_tables(routes, config->listener_count);
    return false;
}
