#include "udp_internal.h"

#include "vane/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static bool worker_configure_capacity(struct udp_worker *worker,
                                      const struct vane_worker_args *args) {
    worker->flow_base_limit = args->udp_flow_base_limit;
    worker->pending_limit = args->udp_pending_limit;
    if (worker->flow_base_limit == 0U || worker->pending_limit == 0U ||
        worker->flow_base_limit > UDP_FLOW_ID_MAX / 2U ||
        worker->pending_limit > (size_t)UINT32_MAX)
        return false;

    worker->flow_capacity = worker->flow_base_limit * 2U;
    worker->flow_limit = worker->flow_base_limit;
    worker->table_capacity = udp_next_power_of_two(worker->flow_capacity * 2U);
    if (worker->table_capacity < 16U) worker->table_capacity = 16U;
    return true;
}

static bool worker_allocate_storage(struct udp_worker *worker) {
    worker->flows = calloc(worker->flow_capacity, sizeof(*worker->flows));
    worker->flow_index = calloc(worker->table_capacity,
                                sizeof(*worker->flow_index));
    worker->free_flow_ids = malloc(worker->flow_capacity *
                                   sizeof(*worker->free_flow_ids));
    worker->reclaim_candidates = malloc(worker->flow_capacity *
                                        sizeof(*worker->reclaim_candidates));
    worker->probes = calloc(worker->pending_limit, sizeof(*worker->probes));
    worker->free_probe_ids = malloc(worker->pending_limit *
                                    sizeof(*worker->free_probe_ids));

    worker->rx_count = worker->args->runtime->recv_batch;
    worker->rx_msgs = calloc(worker->rx_count, sizeof(*worker->rx_msgs));
    worker->rx_iov = calloc(worker->rx_count, sizeof(*worker->rx_iov));
    worker->rx_peers = calloc(worker->rx_count, sizeof(*worker->rx_peers));
    worker->rx_controls = calloc(worker->rx_count, VANE_UDP_CONTROL_SIZE);
    worker->rx_storage = malloc(worker->rx_count * UDP_MAX_PACKET);

    worker->down_capacity = worker->args->runtime->send_batch;
    worker->down = calloc(worker->down_capacity, sizeof(*worker->down));
    worker->tx_msgs = calloc(worker->down_capacity, sizeof(*worker->tx_msgs));
    worker->tx_iov = calloc(worker->down_capacity, sizeof(*worker->tx_iov));
    worker->tx_controls = calloc(worker->down_capacity,
                                 VANE_UDP_CONTROL_SIZE);
    worker->down_storage = malloc(worker->down_capacity * UDP_MAX_PACKET);
    worker->upstream_rx_storage = malloc(UDP_MAX_PACKET);

    return worker->flows != NULL && worker->flow_index != NULL &&
           worker->free_flow_ids != NULL &&
           worker->reclaim_candidates != NULL && worker->probes != NULL &&
           worker->free_probe_ids != NULL && worker->rx_msgs != NULL &&
           worker->rx_iov != NULL && worker->rx_peers != NULL &&
           worker->rx_controls != NULL && worker->rx_storage != NULL &&
           worker->down != NULL && worker->tx_msgs != NULL &&
           worker->tx_iov != NULL && worker->tx_controls != NULL &&
           worker->down_storage != NULL &&
           worker->upstream_rx_storage != NULL;
}

static void worker_initialize_slots(struct udp_worker *worker) {
    for (size_t i = 0; i < worker->flow_capacity; i++) {
        worker->flows[i].state = UDP_FLOW_EMPTY;
        worker->flows[i].upstream_fd = -1;
        worker->flows[i].generation = 1U;
        worker->flows[i].probe_id = UINT32_MAX;
        worker->free_flow_ids[i] = (uint32_t)(worker->flow_capacity - 1U - i);
    }
    worker->free_flow_count = worker->flow_capacity;

    for (size_t i = 0; i < worker->pending_limit; i++)
        worker->free_probe_ids[i] = (uint32_t)(worker->pending_limit - 1U - i);
    worker->free_probe_count = worker->pending_limit;
}

static bool worker_open_listener(struct udp_worker *worker) {
    const struct vane_worker_args *args = worker->args;
    struct vane_error err = {0};
    worker->public_fd = vane_socket_create_listener(
        &args->listener->address, SOCK_DGRAM, IPPROTO_UDP, 0,
        args->runtime->socket_recv_buffer_bytes,
        args->runtime->socket_send_buffer_bytes, &err);
    if (worker->public_fd < 0) {
        LOG_ERROR("UDP worker %zu listener failed: %s",
                  args->worker_index, err.message);
        return false;
    }

    int gro = vane_udp_enable_metadata(
        worker->public_fd, args->listener->address.storage.ss_family, true, &err);
    if (gro < 0) {
        LOG_ERROR("UDP worker %zu metadata setup failed: %s",
                  args->worker_index, err.message);
        return false;
    }
    worker->public_gro = gro > 0;
    worker->public_gso_enabled = true;

    worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epoll_fd < 0) return false;
    struct epoll_event event = {
        .events = EPOLLIN,
        .data.u64 = udp_event_token(UDP_EVENT_PUBLIC, 0U, 0U),
    };
    return epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD,
                     worker->public_fd, &event) == 0;
}

static bool worker_init(struct udp_worker *worker,
                        const struct vane_worker_args *args) {
    memset(worker, 0, sizeof(*worker));
    worker->args = args;
    worker->public_fd = -1;
    worker->epoll_fd = -1;

    if (!worker_configure_capacity(worker, args) ||
        !worker_allocate_storage(worker))
        return false;

    worker_initialize_slots(worker);
    worker->hash_seed = vane_random_u64() ^ (uint64_t)args->worker_index;
    if (!worker_open_listener(worker)) return false;

    worker->next_expiry_scan_ms = vane_monotonic_ms() + 1000U;
    worker->next_capacity_scan_ms = 0U;
    return true;
}

static void worker_destroy(struct udp_worker *worker) {
    udp_downstream_flush(worker);
    if (worker->flows != NULL) {
        for (size_t i = 0; i < worker->flow_capacity; i++) {
            if (worker->flows[i].state == UDP_FLOW_PENDING ||
                worker->flows[i].state == UDP_FLOW_ACTIVE ||
                worker->flows[i].state == UDP_FLOW_REPROBING ||
                worker->flows[i].state == UDP_FLOW_QUIESCENT)
                udp_flow_remove(worker, i);
        }
    }
    if (worker->public_fd >= 0) close(worker->public_fd);
    if (worker->epoll_fd >= 0) close(worker->epoll_fd);

    free(worker->flows);
    free(worker->flow_index);
    free(worker->free_flow_ids);
    free(worker->reclaim_candidates);
    if (worker->probes != NULL) {
        for (size_t i = 0; i < worker->pending_limit; i++) {
            vane_quic_probe_state_free(worker->probes[i].parser);
            free(worker->probes[i].data);
        }
    }
    for (size_t i = 0; i < worker->probe_cache_count; i++)
        free(worker->probe_cache[i]);
    free(worker->probes);
    free(worker->free_probe_ids);

    free(worker->rx_msgs);
    free(worker->rx_iov);
    free(worker->rx_peers);
    free(worker->rx_controls);
    free(worker->rx_storage);
    free(worker->down);
    free(worker->tx_msgs);
    free(worker->tx_iov);
    free(worker->tx_controls);
    free(worker->down_storage);
    free(worker->upstream_rx_storage);
}

void *vane_udp_worker_main(void *opaque) {
    const struct vane_worker_args *args = opaque;
    struct udp_worker worker;
    if (!worker_init(&worker, args)) {
        vane_worker_report_start(args->startup, false);
        worker_destroy(&worker);
        return NULL;
    }

    char addrbuf[96];
    LOG_INFO("UDP worker %zu started address=%s flows=%zu burst=%zu gro=%s",
             args->worker_index,
             vane_addr_format(&args->listener->address,
                                addrbuf, sizeof(addrbuf)),
             worker.flow_base_limit, worker.flow_capacity,
             worker.public_gro ? "on" : "off");
    vane_worker_report_start(args->startup, true);

    struct epoll_event events[UDP_EPOLL_BATCH];
    while (!vane_worker_should_stop(args->startup)) {
        int count = epoll_wait(worker.epoll_fd, events, UDP_EPOLL_BATCH, 100);
        if (count < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("UDP worker %zu epoll_wait failed: %s",
                      args->worker_index, strerror(errno));
            vane_worker_request_stop(args->startup);
            break;
        }

        for (int i = 0; i < count; i++) {
            uint64_t token = events[i].data.u64;
            uint8_t kind = udp_token_kind(token);
            if (kind == UDP_EVENT_PUBLIC) {
                udp_receive_public(&worker);
                continue;
            }
            if (kind != UDP_EVENT_UPSTREAM) continue;

            uint32_t id = udp_token_id(token);
            if (id >= worker.flow_capacity) continue;
            struct udp_flow *flow = &worker.flows[id];
            if ((flow->state != UDP_FLOW_ACTIVE &&
                 flow->state != UDP_FLOW_REPROBING &&
                 flow->state != UDP_FLOW_QUIESCENT) ||
                flow->generation != udp_token_generation(token))
                continue;

            if ((events[i].events & EPOLLIN) != 0)
                udp_receive_upstream(&worker, id);
            if ((events[i].events & (EPOLLERR | EPOLLHUP)) != 0 &&
                (flow->state == UDP_FLOW_ACTIVE ||
                 flow->state == UDP_FLOW_REPROBING ||
                 flow->state == UDP_FLOW_QUIESCENT))
                udp_flow_handle_epoll_error(&worker, id, events[i].events);
        }
        udp_downstream_flush(&worker);
        udp_flow_expire(&worker);
    }

    worker_destroy(&worker);
    return NULL;
}
