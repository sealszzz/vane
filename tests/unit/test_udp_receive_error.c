#include "udp_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);
static size_t transient_errors;
static size_t received_payloads;

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
    if (transient_errors != 0U) {
        transient_errors--;
        errno = ENOBUFS;
        return -1;
    }
    ssize_t n = __real_recvmsg(fd, message, flags);
    if (n >= 0) received_payloads++;
    return n;
}

int main(void) {
    int backend = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int client = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(backend >= 0 && client >= 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(bind(backend, (const struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t len = sizeof(address);
    assert(getsockname(backend, (struct sockaddr *)&address, &len) == 0);
    assert(connect(client, (const struct sockaddr *)&address, len) == 0);
    struct vane_target_config target = {.location_kind = VANE_LOCATION_ADDRESS};
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&address,
                                    len, &target.location));
    struct udp_flow flow = {
        .state = UDP_FLOW_ACTIVE, .upstream_fd = client,
        .upstream_confirmed = true, .target = &target,
    };
    len = sizeof(address);
    assert(getsockname(client, (struct sockaddr *)&address, &len) == 0);
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&address,
                                    len, &flow.upstream_local));
    flow.key.client = flow.upstream_local;
    flow.key.local = target.location;
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET};
    assert(epoll_fd >= 0);
    assert(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &event) == 0);
    assert(sendto(backend, "response", 8U, 0,
                   (const struct sockaddr *)&address, len) == 8);
    close(backend);
    assert(send(client, "ICMP", 4U, 0) == 4);
    assert(epoll_wait(epoll_fd, &event, 1, 100) == 1);
    assert((event.events & EPOLLERR) != 0U);
    struct vane_worker_args args = {0};
    struct udp_worker worker = {
        .args = &args, .flows = &flow, .flow_capacity = 1U,
        .epoll_fd = epoll_fd, .down_capacity = 3U,
    };
    worker.upstream_rx_storage = malloc(UDP_MAX_PACKET);
    worker.down_storage = malloc(3U * UDP_MAX_PACKET);
    worker.down = calloc(3U, sizeof(*worker.down));
    assert(worker.upstream_rx_storage && worker.down_storage && worker.down);
    udp_receive_upstream(&worker, 0U);
    udp_flow_handle_epoll_error(&worker, 0U, event.events);
    assert(flow.state == UDP_FLOW_ACTIVE);
    assert(worker.down_count == 1U && worker.down[0].len == 8U);
    assert(memcmp(worker.down[0].data, "response", 8U) == 0);
    assert(epoll_wait(epoll_fd, &event, 1, 0) == 0);
    char byte;
    assert(recv(client, &byte, 1U, MSG_PEEK | MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    /* Exhaust the error budget with data already ready, then prove rearming
     * schedules another turn without any subsequent arriving datagram. */
    backend = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(backend >= 0);
    assert(bind(backend, (const struct sockaddr *)&target.location.storage,
                target.location.len) == 0);
    assert(sendto(backend, "next", 4U, 0,
                  (const struct sockaddr *)&address, len) == 4);
    assert(epoll_wait(epoll_fd, &event, 1, 100) == 1);
    transient_errors = UDP_RECEIVE_ERROR_QUANTUM;
    udp_receive_upstream(&worker, 0U);
    assert(transient_errors == 0U && worker.down_count == 1U);
    assert(epoll_wait(epoll_fd, &event, 1, 100) == 1);
    udp_receive_upstream(&worker, 0U);
    assert(worker.down_count == 2U && worker.down[1].len == 4U);
    assert(memcmp(worker.down[1].data, "next", 4U) == 0);
    /* Keep more than one receive quantum ready without any later arrivals.
     * The hot flow must yield and still progress on a rearmed ET event. */
    int sink = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    worker.public_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    assert(sink >= 0 && worker.public_fd >= 0);
    struct sockaddr_in sink_address = {
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(bind(sink, (const struct sockaddr *)&sink_address, sizeof(sink_address)) == 0);
    socklen_t sink_len = sizeof(sink_address);
    assert(getsockname(sink, (struct sockaddr *)&sink_address, &sink_len) == 0);
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&sink_address,
                                    sink_len, &flow.key.client));
    worker.tx_msgs = calloc(worker.down_capacity, sizeof(*worker.tx_msgs));
    worker.tx_iov = calloc(worker.down_capacity, sizeof(*worker.tx_iov));
    worker.tx_controls = calloc(worker.down_capacity, VANE_UDP_CONTROL_SIZE);
    assert(worker.tx_msgs && worker.tx_iov && worker.tx_controls);
    worker.down_count = 0U;
    for (size_t i = 0U; i < UDP_UPSTREAM_RECEIVE_QUANTUM + 5U; i++)
        assert(sendto(backend, "hot", 3U, 0,
                       (const struct sockaddr *)&address, len) == 3);
    assert(epoll_wait(epoll_fd, &event, 1, 100) == 1);
    received_payloads = 0U;
    udp_receive_upstream(&worker, 0U);
    assert(received_payloads == UDP_UPSTREAM_RECEIVE_QUANTUM);
    assert(epoll_wait(epoll_fd, &event, 1, 100) == 1);
    udp_receive_upstream(&worker, 0U);
    assert(received_payloads == UDP_UPSTREAM_RECEIVE_QUANTUM + 5U);
    udp_downstream_flush(&worker);
    size_t delivered = 0U;
    char payload[3];
    while (recv(sink, payload, sizeof(payload), MSG_DONTWAIT) == 3) {
        assert(memcmp(payload, "hot", 3U) == 0);
        delivered++;
    }
    assert(delivered == UDP_UPSTREAM_RECEIVE_QUANTUM + 5U);
    close(sink);
    close(worker.public_fd);
    free(worker.tx_msgs);
    free(worker.tx_iov);
    free(worker.tx_controls);
    close(backend);
    close(client);
    close(epoll_fd);
    free(worker.upstream_rx_storage);
    free(worker.down_storage);
    free(worker.down);
    return 0;
}
