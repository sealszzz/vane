#include "udp_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);
static size_t transient_errors;

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
    if (transient_errors != 0U) {
        transient_errors--;
        errno = ENOBUFS;
        return -1;
    }
    return __real_recvmsg(fd, message, flags);
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
    close(backend);
    close(client);
    close(epoll_fd);
    free(worker.upstream_rx_storage);
    free(worker.down_storage);
    free(worker.down);
    return 0;
}
