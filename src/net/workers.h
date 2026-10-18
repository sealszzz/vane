#ifndef VANE_WORKERS_H
#define VANE_WORKERS_H

#include "vane/config.h"
#include "vane/route.h"

#include <pthread.h>
#include <stdatomic.h>

struct vane_worker_startup {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    size_t reported;
    bool failed;
    atomic_bool stop;
};

struct vane_worker_args {
    size_t worker_index;
    const struct vane_listener_config *listener;
    const struct vane_runtime_config *runtime;
    const struct vane_route_table *routes;
    size_t tcp_connection_limit;
    size_t tcp_connecting_limit;
    size_t udp_flow_base_limit;
    size_t udp_pending_limit;
    struct vane_worker_startup *startup;
};

void vane_worker_report_start(struct vane_worker_startup *startup, bool success);
void vane_worker_request_stop(struct vane_worker_startup *startup);
bool vane_worker_should_stop(const struct vane_worker_startup *startup);

void *vane_tcp_worker_main(void *opaque);
void *vane_udp_worker_main(void *opaque);

#endif
