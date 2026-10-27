/* Exercise the real TCP state machine with no later client writes or FIN. */
#include "../../src/net/tcp_worker.c"

#include <assert.h>
#include <stdio.h>

static void test_buffer_limit(void) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    struct io_buffer buffer;
    buffer_init(&buffer, TCP_BUFFER_INITIAL * 2U, NULL);
    assert(buffer_reserve_tail(&buffer, TCP_BUFFER_INITIAL * 2U));
    buffer.max_cap = TCP_BUFFER_INITIAL;
    uint8_t data[TCP_BUFFER_INITIAL * 2U] = {0};
    assert(send(pair[0], data, sizeof(data), 0) == (ssize_t)sizeof(data));
    bool eof = false;
    assert(buffer_read_from_fd(&buffer, pair[1], &eof) == TCP_BUFFER_INITIAL);
    assert(buffer.len == buffer.max_cap && !eof);
    buffer_release(&buffer);
    close(pair[0]);
    close(pair[1]);
}

static void test_probe_transition(bool proxy, bool tls) {
    int backend = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    assert(backend >= 0);
    assert(bind(backend, (const struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(backend, 1) == 0);
    socklen_t address_len = sizeof(address);
    assert(getsockname(backend, (struct sockaddr *)&address, &address_len) == 0);
    struct vane_sni_rule any = {.kind = VANE_SNI_ANY};
    struct vane_target_config targets[2] = {
        {.location_kind = VANE_LOCATION_DROP, .sni = &any, .sni_count = 1U},
        {.location_kind = VANE_LOCATION_ADDRESS, .proxy_protocol = proxy},
    };
    struct sockaddr_storage storage = {0};
    memcpy(&storage, &address, sizeof(address));
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&storage,
                                   address_len, &targets[1].location));
    if (tls) {
        targets[0].location_kind = VANE_LOCATION_ADDRESS;
        targets[0].location = targets[1].location;
        targets[0].proxy_protocol = proxy;
    }
    struct vane_listener_config listener = {.targets = targets, .target_count = 2U};
    struct vane_route_table *routes = NULL;
    struct vane_error err = {0};
    assert(vane_route_table_build(&listener, &routes, &err));
    struct vane_runtime_config runtime = {
        .tcp_probe_timeout_ms = 1000U, .tcp_connect_timeout_ms = 1500U,
    };
    struct vane_worker_args args = {.runtime = &runtime, .routes = routes};
    struct tcp_connection connection = {0};
    uint32_t free_id = 0U;
    struct tcp_worker worker = {
        .args = &args, .epoll_fd = epoll_create1(EPOLL_CLOEXEC),
        .connections = &connection, .free_ids = &free_id, .free_count = 1U,
        .capacity = 1U, .connecting_limit = 1U,
        .probe_max = VANE_TLS_HANDSHAKE_MAX_SIZE,
        .relay_max = TCP_BUFFER_INITIAL, .u2c_max = TCP_BUFFER_INITIAL,
    };
    assert(worker.epoll_fd >= 0);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    assert(allocate_connection(&worker, pair[1], &targets[1].location,
                               &targets[1].location));
    uint8_t data[VANE_TLS_HANDSHAKE_MAX_SIZE + 4096U];
    memset(data, 'X', sizeof(data));
    if (tls) {
        uint8_t hello[50] = {0x16, 3, 3, 0, 45, 1, 0, 0, 41, 3, 3};
        hello[45] = 2U;
        hello[46] = 0x13U;
        hello[47] = 1U;
        hello[48] = 1U;
        memcpy(data, hello, sizeof(hello));
    }
    assert(send(pair[0], data, sizeof(data), 0) == (ssize_t)sizeof(data));
    struct epoll_event event;
    assert(epoll_wait(worker.epoll_fd, &event, 1, 100) == 1);
    assert(token_kind(event.data.u64) == TCP_EVENT_CLIENT);
    handle_client_event(&worker, 0U, event.events);
    assert(connection.state != CONN_FREE);
    size_t expected = sizeof(data) + (proxy ? 28U : 0U), received = 0U;
    int peer = -1;
    for (unsigned turn = 0U; turn < 20U && received < expected; turn++) {
        if (peer < 0) peer = accept4(backend, NULL, NULL, SOCK_NONBLOCK);
        int ready = epoll_wait(worker.epoll_fd, &event, 1, 20);
        assert(ready >= 0);
        if (ready != 0) {
            if (token_kind(event.data.u64) == TCP_EVENT_CLIENT)
                handle_client_event(&worker, 0U, event.events);
            else handle_upstream_event(&worker, 0U, event.events);
        }
        if (peer >= 0) {
            uint8_t buffer[8192];
            ssize_t n;
            while ((n = recv(peer, buffer, sizeof(buffer), 0)) > 0)
                received += (size_t)n;
        }
    }
    assert(received == expected);
    close_connection(&worker, 0U);
    for (size_t i = 0; i < worker.buffer_cache.count; i++)
        free(worker.buffer_cache.blocks[i]);
    close(worker.epoll_fd);
    close(pair[0]);
    if (peer >= 0) close(peer);
    close(backend);
    vane_route_table_destroy(routes);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "limit") == 0) test_buffer_limit();
    else {
        test_probe_transition(false, false);
        test_probe_transition(true, false);
        test_probe_transition(false, true);
        test_probe_transition(true, true);
        test_buffer_limit();
    }
    puts("TCP probe transition and logical buffer limit passed");
    return 0;
}
