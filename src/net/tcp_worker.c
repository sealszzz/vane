#include "workers.h"

#include "vane/linux_net.h"
#include "vane/log.h"
#include "vane/proxy_protocol.h"
#include "vane/tls_parser.h"

#include <errno.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define TCP_EVENT_LISTENER 1U
#define TCP_EVENT_CLIENT 2U
#define TCP_EVENT_UPSTREAM 3U
#define TCP_EVENT_BATCH 256
#define TCP_ACCEPT_QUANTUM 128U
#define TCP_BUFFER_INITIAL (16U * 1024U)
#define TCP_BUFFER_CACHE_LIMIT 16U
#define TCP_EXPIRY_SCAN_INTERVAL_MS 100U

struct tcp_buffer_cache {
    uint8_t *blocks[TCP_BUFFER_CACHE_LIMIT];
    size_t count;
};

enum connection_state {
    CONN_FREE = 0,
    CONN_PROBING,
    CONN_CONNECTING,
    CONN_RELAYING,
};

enum prefix_class {
    PREFIX_NEED_MORE = 0,
    PREFIX_TLS_LIKE,
    PREFIX_NON_TLS,
};

struct io_buffer {
    uint8_t *data;
    size_t cap;
    size_t max_cap;
    size_t off;
    size_t len;
    struct tcp_buffer_cache *cache;
};

struct tcp_connection {
    enum connection_state state;
    uint32_t generation;
    int client_fd;
    int upstream_fd;
    struct vane_addr client_addr;
    struct vane_addr local_addr;
    const struct vane_target_config *target;
    struct io_buffer c2u;
    struct io_buffer u2c;
    uint64_t deadline_ms;
    uint64_t last_activity_ms;
    uint32_t client_events;
    uint32_t upstream_events;
    bool client_eof;
    bool upstream_eof;
    bool client_write_shutdown;
    bool upstream_write_shutdown;
};

struct tcp_worker {
    const struct vane_worker_args *args;
    int epoll_fd;
    int listener_fd;
    struct tcp_connection *connections;
    uint32_t *free_ids;
    size_t free_count;
    size_t capacity;
    size_t probe_max;
    size_t relay_max;
    size_t u2c_max;
    size_t connecting_count;
    size_t connecting_limit;
    struct tcp_buffer_cache buffer_cache;
};

static uint64_t event_token(uint8_t kind, uint32_t id, uint32_t generation) {
    return ((uint64_t)kind << 56) | ((uint64_t)generation << 24) |
           (uint64_t)(id & 0x00ffffffU);
}

static uint8_t token_kind(uint64_t token) { return (uint8_t)(token >> 56); }
static uint32_t token_generation(uint64_t token) { return (uint32_t)(token >> 24); }
static uint32_t token_id(uint64_t token) { return (uint32_t)(token & 0x00ffffffU); }

static enum prefix_class classify_prefix(const struct io_buffer *buffer) {
    if (buffer->len < 3U) return PREFIX_NEED_MORE;
    const uint8_t *p = buffer->data + buffer->off;
    return p[0] == 0x16U && p[1] == 0x03U && p[2] <= 0x04U
        ? PREFIX_TLS_LIKE : PREFIX_NON_TLS;
}

static size_t buffer_tail_space(const struct io_buffer *buffer) {
    return buffer->cap - (buffer->off + buffer->len);
}

static void buffer_compact(struct io_buffer *buffer) {
    if (buffer->off != 0U && buffer->len != 0U)
        memmove(buffer->data, buffer->data + buffer->off, buffer->len);
    buffer->off = 0U;
}

static uint8_t *buffer_cache_acquire(struct tcp_buffer_cache *cache) {
    if (cache != NULL && cache->count != 0U)
        return cache->blocks[--cache->count];
    return malloc(TCP_BUFFER_INITIAL);
}

static void buffer_release(struct io_buffer *buffer) {
    if (buffer->data != NULL && buffer->cap == TCP_BUFFER_INITIAL &&
        buffer->cache != NULL && buffer->cache->count < TCP_BUFFER_CACHE_LIMIT) {
        buffer->cache->blocks[buffer->cache->count++] = buffer->data;
    } else {
        free(buffer->data);
    }
    buffer->data = NULL;
    buffer->cap = 0U;
    buffer->off = 0U;
    buffer->len = 0U;
}

static void buffer_trim_empty(struct io_buffer *buffer) {
    if (buffer->len != 0U || buffer->cap <= TCP_BUFFER_INITIAL) return;
    free(buffer->data);
    buffer->data = NULL;
    buffer->cap = 0U;
    buffer->off = 0U;
}

static bool buffer_reserve_tail(struct io_buffer *buffer, size_t required) {
    if (required <= buffer_tail_space(buffer)) return true;
    if (buffer->off != 0U) buffer_compact(buffer);
    if (required <= buffer_tail_space(buffer)) return true;
    if (buffer->len > buffer->max_cap || required > buffer->max_cap - buffer->len)
        return false;
    size_t wanted = buffer->len + required;
    size_t new_cap = buffer->cap == 0U ? VANE_MIN(TCP_BUFFER_INITIAL, buffer->max_cap)
                                       : buffer->cap;
    while (new_cap < wanted) {
        size_t next = new_cap > SIZE_MAX / 2U ? buffer->max_cap : new_cap * 2U;
        if (next > buffer->max_cap) next = buffer->max_cap;
        if (next <= new_cap) return false;
        new_cap = next;
    }
    uint8_t *data;
    if (buffer->data == NULL && new_cap == TCP_BUFFER_INITIAL) {
        data = buffer_cache_acquire(buffer->cache);
    } else {
        data = realloc(buffer->data, new_cap);
    }
    if (data == NULL) return false;
    buffer->data = data;
    buffer->cap = new_cap;
    return true;
}

static void buffer_init(struct io_buffer *buffer, size_t max_cap,
                        struct tcp_buffer_cache *cache) {
    memset(buffer, 0, sizeof(*buffer));
    buffer->max_cap = max_cap;
    buffer->cache = cache;
}

static ssize_t buffer_read_from_fd(struct io_buffer *buffer, int fd, bool *eof) {
    ssize_t total = 0;
    for (;;) {
        /* A probe allocation can outlive a reduction of the logical limit. */
        if (buffer->len >= buffer->max_cap) return total;
        if (buffer_tail_space(buffer) == 0U) {
            if (!buffer_reserve_tail(buffer, 1U)) { errno = ENOMEM; return -1; }
        }
        size_t space = VANE_MIN(buffer_tail_space(buffer),
                                buffer->max_cap - buffer->len);
        if (space == 0U) return total;
        ssize_t n = recv(fd, buffer->data + buffer->off + buffer->len,
                         space, MSG_DONTWAIT);
        if (n > 0) {
            buffer->len += (size_t)n;
            total += n;
            continue;
        }
        if (n == 0) { *eof = true; return total; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
        return -1;
    }
}

static ssize_t buffer_write_to_fd(struct io_buffer *buffer, int fd) {
    ssize_t total = 0;
    while (buffer->len != 0U) {
        ssize_t n = send(fd, buffer->data + buffer->off, buffer->len,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            buffer->off += (size_t)n;
            buffer->len -= (size_t)n;
            total += n;
            if (buffer->len == 0U) buffer->off = 0U;
            continue;
        }
        if (n == 0) return total;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
        return -1;
    }
    return total;
}

static bool connection_read(struct tcp_connection *c, struct io_buffer *buffer,
                            int fd, bool *eof) {
    ssize_t n = buffer_read_from_fd(buffer, fd, eof);
    if (n < 0) return false;
    if (n > 0) c->last_activity_ms = vane_monotonic_ms();
    return true;
}

static bool connection_write(struct tcp_connection *c, struct io_buffer *buffer,
                             int fd) {
    ssize_t n = buffer_write_to_fd(buffer, fd);
    if (n < 0) return false;
    if (n > 0) c->last_activity_ms = vane_monotonic_ms();
    if (buffer->len == 0U) buffer_trim_empty(buffer);
    return true;
}

static bool epoll_mod_if_changed(int epoll_fd, int fd, uint32_t events,
                                 uint64_t token, uint32_t *registered) {
    if (*registered == events) return true;
    struct epoll_event ev = {.events = events, .data.u64 = token};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) return false;
    *registered = events;
    return true;
}

static bool epoll_add(int epoll_fd, int fd, uint32_t events, uint64_t token) {
    struct epoll_event ev = {.events = events, .data.u64 = token};
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
}

static void epoll_del(int epoll_fd, int fd) {
    if (fd >= 0) (void)epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static void close_connection(struct tcp_worker *worker, uint32_t id) {
    struct tcp_connection *c = &worker->connections[id];
    if (c->state == CONN_FREE) return;
    if (c->state == CONN_CONNECTING && worker->connecting_count != 0)
        worker->connecting_count--;
    epoll_del(worker->epoll_fd, c->client_fd);
    epoll_del(worker->epoll_fd, c->upstream_fd);
    if (c->client_fd >= 0) close(c->client_fd);
    if (c->upstream_fd >= 0) close(c->upstream_fd);
    buffer_release(&c->c2u);
    buffer_release(&c->u2c);
    uint32_t generation = c->generation + 1U;
    if (generation == 0) generation = 1U;
    memset(c, 0, sizeof(*c));
    c->state = CONN_FREE;
    c->client_fd = -1;
    c->upstream_fd = -1;
    c->generation = generation;
    worker->free_ids[worker->free_count++] = id;
}

static bool update_interests(struct tcp_worker *worker, uint32_t id) {
    struct tcp_connection *c = &worker->connections[id];
    uint64_t ctok = event_token(TCP_EVENT_CLIENT, id, c->generation);
    uint32_t cevents = EPOLLET;
    if (!c->client_eof) {
        cevents |= EPOLLRDHUP;
        if (c->c2u.len < c->c2u.max_cap) cevents |= EPOLLIN;
    }
    if (c->u2c.len != 0U) cevents |= EPOLLOUT;
    if (!epoll_mod_if_changed(worker->epoll_fd, c->client_fd, cevents, ctok,
                              &c->client_events)) {
        LOG_WARN("TCP worker %zu connection %u client epoll update failed: %s",
                 worker->args->worker_index, id, strerror(errno));
        return false;
    }

    if (c->upstream_fd >= 0) {
        uint64_t utok = event_token(TCP_EVENT_UPSTREAM, id, c->generation);
        uint32_t uevents = EPOLLET;
        if (c->state == CONN_CONNECTING) {
            uevents |= EPOLLOUT | EPOLLRDHUP;
        } else {
            if (!c->upstream_eof) {
                uevents |= EPOLLRDHUP;
                if (c->u2c.len < c->u2c.max_cap) uevents |= EPOLLIN;
            }
            if (c->c2u.len != 0U) uevents |= EPOLLOUT;
        }
        if (!epoll_mod_if_changed(worker->epoll_fd, c->upstream_fd, uevents,
                                  utok, &c->upstream_events)) {
            LOG_WARN("TCP worker %zu connection %u upstream epoll update failed: %s",
                     worker->args->worker_index, id, strerror(errno));
            return false;
        }
    }
    return true;
}

static bool refresh_connection(struct tcp_worker *worker, uint32_t id) {
    if (update_interests(worker, id)) return true;
    close_connection(worker, id);
    return false;
}

static bool prepend_proxy_header(struct tcp_connection *c,
                                 struct vane_error *err) {
    if (!c->target->proxy_protocol) return true;
    struct vane_proxy_header header;
    if (!vane_proxy_v2_encode(&c->client_addr, &c->local_addr,
                                VANE_PROXY_STREAM, &header, err)) return false;
    if (!buffer_reserve_tail(&c->c2u, header.len)) {
        vane_error_set(err, "TCP relay buffer cannot hold PROXY header");
        return false;
    }
    buffer_compact(&c->c2u);
    memmove(c->c2u.data + header.len, c->c2u.data, c->c2u.len);
    memcpy(c->c2u.data, header.bytes, header.len);
    c->c2u.len += header.len;
    return true;
}

static bool configure_stream_socket(int fd,
                                    const struct vane_runtime_config *rt) {
    int one = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
        return false;
    if (rt->tcp_keepalive_idle_secs != 0U ||
        rt->tcp_keepalive_interval_secs != 0U) {
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) != 0)
            return false;
        if (rt->tcp_keepalive_idle_secs != 0U) {
            int idle = rt->tcp_keepalive_idle_secs > (uint64_t)INT_MAX
                ? INT_MAX : (int)rt->tcp_keepalive_idle_secs;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) != 0)
                return false;
        }
        if (rt->tcp_keepalive_interval_secs != 0U) {
            int interval = rt->tcp_keepalive_interval_secs > (uint64_t)INT_MAX
                ? INT_MAX : (int)rt->tcp_keepalive_interval_secs;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval,
                           sizeof(interval)) != 0)
                return false;
        }
    }
    return true;
}

static bool begin_connect(struct tcp_worker *worker, uint32_t id,
                          const struct vane_target_config *target) {
    struct tcp_connection *c = &worker->connections[id];
    if (target == NULL || target->location_kind == VANE_LOCATION_DROP) {
        LOG_DEBUG("TCP worker %zu connection %u route=%s",
                  worker->args->worker_index, id,
                  target == NULL ? "unmatched" : "drop");
        close_connection(worker, id);
        return false;
    }
    if (worker->connecting_count >= worker->connecting_limit) {
        LOG_DEBUG("TCP worker %zu connection %u dropped: connecting limit reached",
                  worker->args->worker_index, id);
        close_connection(worker, id);
        return false;
    }
    c->target = target;
    if (c->c2u.len > SIZE_MAX - sizeof(struct vane_proxy_header)) {
        close_connection(worker, id);
        return false;
    }
    /* The probe read may have stopped at its old limit without EAGAIN.
     * Preserve that fact before adding PROXY headroom changes max_cap;
     * refresh_connection must recheck any unread client bytes under ET. */
    if (!c->client_eof && c->c2u.len >= c->c2u.max_cap)
        c->client_events = 0U;
    c->c2u.max_cap = VANE_MAX(worker->relay_max,
        c->c2u.len + sizeof(struct vane_proxy_header));
    struct vane_error err = {0};
    if (!prepend_proxy_header(c, &err)) {
        LOG_DEBUG("TCP worker %zu proxy header failed: %s",
                  worker->args->worker_index, err.message);
        close_connection(worker, id);
        return false;
    }
    int family = target->location.storage.ss_family;
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0 || !configure_stream_socket(fd, worker->args->runtime)) {
        LOG_DEBUG("TCP worker %zu connection %u upstream socket failed: %s",
                  worker->args->worker_index, id, strerror(errno));
        if (fd >= 0) close(fd);
        close_connection(worker, id);
        return false;
    }
    c->upstream_fd = fd;
    c->state = CONN_CONNECTING;
    worker->connecting_count++;
    c->deadline_ms = vane_monotonic_ms() + worker->args->runtime->tcp_connect_timeout_ms;
    c->upstream_events = EPOLLOUT | EPOLLRDHUP | EPOLLET;
    if (!epoll_add(worker->epoll_fd, fd, c->upstream_events,
                   event_token(TCP_EVENT_UPSTREAM, id, c->generation))) {
        c->upstream_events = 0U;
        LOG_DEBUG("TCP worker %zu connection %u upstream epoll add failed: %s",
                  worker->args->worker_index, id, strerror(errno));
        close_connection(worker, id);
        return false;
    }
    int rc = connect(fd, (const struct sockaddr *)&target->location.storage,
                     target->location.len);
    if (rc == 0) {
        c->state = CONN_RELAYING;
        if (worker->connecting_count != 0) worker->connecting_count--;
        c->deadline_ms = 0;
    } else if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR) {
        LOG_DEBUG("TCP worker %zu connection %u connect failed: %s",
                  worker->args->worker_index, id, strerror(errno));
        close_connection(worker, id);
        return false;
    }
    char upstream[96];
    LOG_DEBUG("TCP worker %zu connection %u selected upstream=%s proxy=%s",
              worker->args->worker_index, id,
              vane_addr_format(&target->location, upstream, sizeof(upstream)),
              target->proxy_protocol ? "on" : "off");
    return refresh_connection(worker, id);
}

static bool route_probe(struct tcp_worker *worker, uint32_t id,
                        bool eof_or_timeout) {
    struct tcp_connection *c = &worker->connections[id];
    enum prefix_class cls = classify_prefix(&c->c2u);
    if (cls == PREFIX_NON_TLS) {
        return begin_connect(worker, id,
            vane_route_select_fallback(worker->args->routes));
    }
    if (cls == PREFIX_NEED_MORE) {
        if (!eof_or_timeout) return true;
        if (c->c2u.len != 0) {
            return begin_connect(worker, id,
                vane_route_select_fallback(worker->args->routes));
        }
        close_connection(worker, id);
        return false;
    }

    struct vane_client_hello hello;
    struct vane_error err = {0};
    enum vane_probe_result result = vane_tls_parse_records(
        c->c2u.data + c->c2u.off, c->c2u.len, &hello, &err);
    if (result == VANE_PROBE_MATCHED) {
        const struct vane_target_config *target =
            vane_route_select_tls(worker->args->routes, &hello);
        LOG_DEBUG("TCP worker %zu connection %u ClientHello sni=%s",
                  worker->args->worker_index, id,
                  hello.has_sni ? hello.server_name : "none");
        return begin_connect(worker, id, target);
    }
    if (result == VANE_PROBE_NOT_PROTOCOL) {
        return begin_connect(worker, id,
            vane_route_select_fallback(worker->args->routes));
    }
    if (result == VANE_PROBE_MALFORMED || eof_or_timeout ||
        c->c2u.len == c->c2u.max_cap) {
        close_connection(worker, id);
        return false;
    }
    return true;
}

static bool finish_connect(struct tcp_worker *worker, uint32_t id) {
    struct tcp_connection *c = &worker->connections[id];
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(c->upstream_fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        close_connection(worker, id);
        return false;
    }
    c->state = CONN_RELAYING;
    if (worker->connecting_count != 0) worker->connecting_count--;
    c->deadline_ms = 0U;
    return true;
}

static bool shutdown_write_once(int fd, bool *done) {
    if (*done || fd < 0) return true;
    if (shutdown(fd, SHUT_WR) == 0) {
        *done = true;
        return true;
    }
    return false;
}

static bool maybe_half_close(struct tcp_connection *c) {
    /* A client can send FIN while the nonblocking upstream connect is still
     * pending.  Calling shutdown(2) at that point returns ENOTCONN and loses
     * the FIN permanently.  Propagate it only after connect completion. */
    if (c->state == CONN_RELAYING && c->client_eof && c->c2u.len == 0 &&
        !shutdown_write_once(c->upstream_fd, &c->upstream_write_shutdown))
        return false;
    if (c->upstream_eof && c->u2c.len == 0 &&
        !shutdown_write_once(c->client_fd, &c->client_write_shutdown))
        return false;
    return true;
}

static bool relay_done(const struct tcp_connection *c) {
    return c->client_eof && c->upstream_eof &&
           c->c2u.len == 0 && c->u2c.len == 0;
}

static void flush_relay(struct tcp_worker *worker, uint32_t id) {
    struct tcp_connection *c = &worker->connections[id];
    if (c->state != CONN_RELAYING) {
        (void)refresh_connection(worker, id);
        return;
    }
    bool client_full = c->c2u.len >= c->c2u.max_cap;
    bool upstream_full = c->u2c.len >= c->u2c.max_cap;
    if ((c->c2u.len != 0U &&
         !connection_write(c, &c->c2u, c->upstream_fd)) ||
        (c->u2c.len != 0U &&
         !connection_write(c, &c->u2c, c->client_fd))) {
        close_connection(worker, id);
        return;
    }
    if (c->c2u.len == 0U) c->c2u.max_cap = worker->relay_max;
    /* A read stopped at the buffer limit, before observing EAGAIN. A direct
     * write may free space without changing the interest mask. Force MOD in
     * that case: it rechecks readiness for any unread bytes under EPOLLET. */
    if (client_full && !c->client_eof && c->c2u.len < c->c2u.max_cap)
        c->client_events = 0U;
    if (upstream_full && !c->upstream_eof && c->u2c.len < c->u2c.max_cap)
        c->upstream_events = 0U;
    if (!maybe_half_close(c)) {
        close_connection(worker, id);
        return;
    }
    if (relay_done(c)) close_connection(worker, id);
    else (void)refresh_connection(worker, id);
}

static void handle_client_event(struct tcp_worker *worker, uint32_t id,
                                uint32_t events) {
    struct tcp_connection *c = &worker->connections[id];
    if (c->state == CONN_PROBING) {
        if ((events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0) {
            if (!connection_read(c, &c->c2u, c->client_fd, &c->client_eof)) {
                close_connection(worker, id);
                return;
            }
            if (!route_probe(worker, id, c->client_eof)) return;
        }
        if ((events & EPOLLERR) != 0) close_connection(worker, id);
        else if (c->state != CONN_FREE) flush_relay(worker, id);
        return;
    }
    if ((events & EPOLLIN) != 0 && !c->client_eof) {
        if (!connection_read(c, &c->c2u, c->client_fd, &c->client_eof)) {
            close_connection(worker, id);
            return;
        }
    }
    if ((events & (EPOLLRDHUP | EPOLLHUP)) != 0 && !c->client_eof) {
        if (!connection_read(c, &c->c2u, c->client_fd, &c->client_eof)) {
            close_connection(worker, id);
            return;
        }
    }
    if ((events & EPOLLERR) != 0) {
        close_connection(worker, id);
        return;
    }
    flush_relay(worker, id);
}

static void handle_upstream_event(struct tcp_worker *worker, uint32_t id,
                                  uint32_t events) {
    struct tcp_connection *c = &worker->connections[id];
    if (c->state == CONN_CONNECTING) {
        if ((events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) != 0 &&
            !finish_connect(worker, id)) return;
    }
    if (c->state != CONN_RELAYING) return;
    if ((events & EPOLLIN) != 0 && !c->upstream_eof) {
        if (!connection_read(c, &c->u2c, c->upstream_fd, &c->upstream_eof)) {
            close_connection(worker, id);
            return;
        }
    }
    if ((events & (EPOLLRDHUP | EPOLLHUP)) != 0 && !c->upstream_eof) {
        if (!connection_read(c, &c->u2c, c->upstream_fd, &c->upstream_eof)) {
            close_connection(worker, id);
            return;
        }
    }
    if ((events & EPOLLERR) != 0) {
        close_connection(worker, id);
        return;
    }
    flush_relay(worker, id);
}

static bool allocate_connection(struct tcp_worker *worker, int client_fd,
                                const struct vane_addr *client,
                                const struct vane_addr *local) {
    if (worker->free_count == 0) { close(client_fd); return false; }
    uint32_t id = worker->free_ids[--worker->free_count];
    struct tcp_connection *c = &worker->connections[id];
    uint32_t generation = c->generation == 0 ? 1U : c->generation;
    memset(c, 0, sizeof(*c));
    /* A connection only becomes CONNECTING after begin_connect() has
     * installed its upstream fd and incremented connecting_count. */
    c->state = CONN_PROBING;
    c->generation = generation;
    c->client_fd = client_fd;
    c->upstream_fd = -1;
    c->client_addr = *client;
    c->local_addr = *local;
    buffer_init(&c->c2u, worker->probe_max, &worker->buffer_cache);
    buffer_init(&c->u2c, worker->u2c_max, &worker->buffer_cache);
    c->last_activity_ms = vane_monotonic_ms();
    c->deadline_ms = c->last_activity_ms + worker->args->runtime->tcp_probe_timeout_ms;
    c->client_events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    if (!epoll_add(worker->epoll_fd, client_fd, c->client_events,
                   event_token(TCP_EVENT_CLIENT, id, c->generation))) {
        c->client_events = 0U;
        close_connection(worker, id);
        return false;
    }
    if (!vane_route_has_protocol_rules(worker->args->routes)) {
        return begin_connect(worker, id,
            vane_route_select_fallback(worker->args->routes));
    }
    return true;
}

static void accept_clients(struct tcp_worker *worker) {
    size_t accepted = 0U;
    while (accepted < TCP_ACCEPT_QUANTUM) {
        struct sockaddr_storage peer_storage;
        socklen_t peer_len = sizeof(peer_storage);
        int fd = accept4(worker->listener_fd, (struct sockaddr *)&peer_storage,
                         &peer_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            LOG_WARN("TCP worker %zu accept4 failed: %s",
                     worker->args->worker_index, strerror(errno));
            return;
        }
        accepted++;
        struct vane_addr client, local;
        struct sockaddr_storage local_storage;
        socklen_t local_len = sizeof(local_storage);
        if (!vane_addr_from_sockaddr((struct sockaddr *)&peer_storage, peer_len, &client) ||
            getsockname(fd, (struct sockaddr *)&local_storage, &local_len) != 0 ||
            !vane_addr_from_sockaddr((struct sockaddr *)&local_storage, local_len, &local) ||
            !configure_stream_socket(fd, worker->args->runtime)) {
            close(fd);
            continue;
        }
        (void)allocate_connection(worker, fd, &client, &local);
    }
}

static void expire_connections(struct tcp_worker *worker, uint64_t now) {
    const uint64_t half_close_idle =
        worker->args->runtime->tcp_half_close_idle_timeout_ms;
    for (uint32_t id = 0; id < worker->capacity; id++) {
        struct tcp_connection *c = &worker->connections[id];
        if (c->state == CONN_FREE) continue;
        if (c->deadline_ms != 0U && now >= c->deadline_ms) {
            if (c->state == CONN_PROBING) (void)route_probe(worker, id, true);
            else close_connection(worker, id);
            continue;
        }
        if (c->state == CONN_RELAYING &&
            (c->client_eof || c->upstream_eof) &&
            now - c->last_activity_ms >= half_close_idle) {
            close_connection(worker, id);
        }
    }
}

void *vane_tcp_worker_main(void *opaque) {
    const struct vane_worker_args *args = opaque;
    bool startup_reported = false;
    struct tcp_worker worker;
    memset(&worker, 0, sizeof(worker));
    worker.args = args;
    worker.listener_fd = -1;
    worker.epoll_fd = -1;
    size_t capacity = args->tcp_connection_limit;
    if (capacity == 0U || capacity > 0x00ffffffU) goto done;
    worker.capacity = capacity;
    worker.connecting_limit = args->tcp_connecting_limit;
    worker.probe_max = args->runtime->tcp_probe_buffer_bytes;
    worker.relay_max = args->runtime->tcp_relay_buffer_bytes;
    worker.u2c_max = worker.relay_max;
    worker.connections = calloc(capacity, sizeof(*worker.connections));
    worker.free_ids = calloc(capacity, sizeof(*worker.free_ids));
    if (worker.connections == NULL || worker.free_ids == NULL) goto done;
    for (size_t i = 0; i < capacity; i++) {
        worker.connections[i].state = CONN_FREE;
        worker.connections[i].client_fd = -1;
        worker.connections[i].upstream_fd = -1;
        worker.connections[i].generation = 1U;
        worker.free_ids[i] = (uint32_t)(capacity - i - 1U);
    }
    worker.free_count = capacity;
    struct vane_error err = {0};
    worker.listener_fd = vane_socket_create_listener(&args->listener->address,
        SOCK_STREAM, IPPROTO_TCP, (int)args->runtime->tcp_listen_backlog,
        0U, 0U, &err);
    if (worker.listener_fd < 0) {
        LOG_ERROR("TCP worker %zu listener failed: %s", args->worker_index, err.message);
        goto done;
    }
    worker.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker.epoll_fd < 0 ||
        !epoll_add(worker.epoll_fd, worker.listener_fd, EPOLLIN,
                   event_token(TCP_EVENT_LISTENER, 0, 0))) {
        LOG_ERROR("TCP worker %zu epoll setup failed: %s",
                  args->worker_index, strerror(errno));
        goto done;
    }
    char addrbuf[96];
    LOG_INFO("TCP worker %zu started address=%s capacity=%zu",
             args->worker_index,
             vane_addr_format(&args->listener->address, addrbuf, sizeof(addrbuf)),
             capacity);
    vane_worker_report_start(args->startup, true);
    startup_reported = true;
    struct epoll_event events[TCP_EVENT_BATCH];
    uint64_t next_expiry_scan_ms =
        vane_monotonic_ms() + TCP_EXPIRY_SCAN_INTERVAL_MS;
    while (!vane_worker_should_stop(args->startup)) {
        int n = epoll_wait(worker.epoll_fd, events, TCP_EVENT_BATCH,
                           (int)TCP_EXPIRY_SCAN_INTERVAL_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("TCP worker %zu epoll_wait failed: %s",
                      args->worker_index, strerror(errno));
            vane_worker_request_stop(args->startup);
            break;
        }
        for (int i = 0; i < n; i++) {
            uint64_t token = events[i].data.u64;
            uint8_t kind = token_kind(token);
            if (kind == TCP_EVENT_LISTENER) {
                accept_clients(&worker);
                continue;
            }
            uint32_t id = token_id(token);
            if (id >= worker.capacity) continue;
            struct tcp_connection *c = &worker.connections[id];
            if (c->state == CONN_FREE || c->generation != token_generation(token)) continue;
            if (kind == TCP_EVENT_CLIENT) handle_client_event(&worker, id, events[i].events);
            else if (kind == TCP_EVENT_UPSTREAM) handle_upstream_event(&worker, id, events[i].events);
        }
        uint64_t now = vane_monotonic_ms();
        if (now >= next_expiry_scan_ms) {
            expire_connections(&worker, now);
            next_expiry_scan_ms = now + TCP_EXPIRY_SCAN_INTERVAL_MS;
        }
    }
done:
    if (!startup_reported)
        vane_worker_report_start(args->startup, false);
    if (worker.connections != NULL) {
        for (uint32_t i = 0; i < worker.capacity; i++)
            if (worker.connections[i].state != CONN_FREE) close_connection(&worker, i);
    }
    if (worker.listener_fd >= 0) close(worker.listener_fd);
    if (worker.epoll_fd >= 0) close(worker.epoll_fd);
    free(worker.connections);
    free(worker.free_ids);
    for (size_t i = 0; i < worker.buffer_cache.count; i++)
        free(worker.buffer_cache.blocks[i]);
    return NULL;
}
