#include "udp_internal.h"

#include <assert.h>
#include <errno.h>
#include <linux/udp.h>
#include <stdlib.h>
#include <string.h>

enum send_mode { SEND_OK, GSO_FAIL, PLAIN_FAIL, PARTIAL_BACKPRESSURE,
                 PARTIAL_GSO_FAIL };
static enum send_mode mode;
static size_t mmsg_calls, msg_calls, delivered;
static size_t lengths[128];
static bool saw_gso;

int __wrap_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags);
ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags);

static bool message_has_gso(struct msghdr *message) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(message); c != NULL;
         c = CMSG_NXTHDR(message, c))
        if (c->cmsg_level == IPPROTO_UDP && c->cmsg_type == UDP_SEGMENT)
            return true;
    return false;
}

int __wrap_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags) {
    VANE_UNUSED(fd); VANE_UNUSED(flags);
    assert(count > 0U);
    mmsg_calls++;
    bool gso = message_has_gso(&messages[0].msg_hdr);
    saw_gso = saw_gso || gso;
    if ((mode == GSO_FAIL && mmsg_calls == 1U) ||
        (mode == PARTIAL_GSO_FAIL && mmsg_calls == 2U)) {
        assert(gso);
        errno = EINVAL;
        return -1;
    }
    if (mode == PLAIN_FAIL && mmsg_calls == 1U) {
        assert(!gso);
        errno = EINVAL;
        return -1;
    }
    if (mode == PARTIAL_BACKPRESSURE && mmsg_calls == 2U) {
        errno = ENOBUFS;
        return -1;
    }
    unsigned int sent = count;
    if ((mode == PARTIAL_BACKPRESSURE || mode == PARTIAL_GSO_FAIL) &&
        mmsg_calls == 1U)
        sent = 1U;
    for (unsigned int i = 0U; i < sent; i++) {
        struct msghdr *message = &messages[i].msg_hdr;
        assert(message->msg_iovlen == 1U && delivered < VANE_ARRAY_LEN(lengths));
        lengths[delivered++] = message->msg_iov[0].iov_len;
    }
    return (int)sent;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags) {
    VANE_UNUSED(fd); VANE_UNUSED(message); VANE_UNUSED(flags);
    msg_calls++;
    errno = EIO;
    return -1;
}

static void reset_sender(enum send_mode new_mode) {
    mode = new_mode;
    mmsg_calls = msg_calls = delivered = 0U;
    saw_gso = false;
    memset(lengths, 0, sizeof(lengths));
}

static void init_worker(struct udp_worker *worker, struct vane_worker_args *args,
                         struct udp_flow *flow) {
    memset(worker, 0, sizeof(*worker));
    memset(args, 0, sizeof(*args));
    memset(flow, 0, sizeof(*flow));
    worker->args = args;
    worker->public_fd = -1;
    worker->public_gso_enabled = true;
    worker->down_capacity = 16U;
    worker->down = calloc(16U, sizeof(*worker->down));
    worker->tx_msgs = calloc(16U, sizeof(*worker->tx_msgs));
    worker->tx_iov = calloc(16U, sizeof(*worker->tx_iov));
    worker->tx_controls = calloc(16U, VANE_UDP_CONTROL_SIZE);
    worker->down_storage = malloc(16U * UDP_MAX_PACKET);
    assert(worker->down && worker->tx_msgs && worker->tx_iov &&
           worker->tx_controls && worker->down_storage);
    struct vane_error err = {0};
    assert(vane_addr_parse("127.0.0.1:12000", false, &flow->key.client, &err));
    assert(vane_addr_parse("127.0.0.1:1443", false, &flow->key.local, &err));
}

static void destroy_worker(struct udp_worker *worker) {
    free(worker->down); free(worker->tx_msgs); free(worker->tx_iov);
    free(worker->tx_controls); free(worker->down_storage);
}

int main(void) {
    assert(udp_gso_error_disables(EINVAL));
    assert(udp_gso_error_disables(EMSGSIZE));
    assert(udp_gso_error_disables(ENOPROTOOPT));
    assert(udp_gso_error_allows_fallback(EINVAL));
    assert(!udp_gso_error_allows_fallback(ENOBUFS));
    assert(!udp_gso_error_disables(EAGAIN));
    struct udp_worker worker;
    struct vane_worker_args args;
    struct udp_flow flow;
    init_worker(&worker, &args, &flow);
    uint8_t payload[2500] = {0};

    reset_sender(GSO_FAIL);
    udp_downstream_queue(&worker, &flow, payload, sizeof(payload), 1200U, 2U, true);
    udp_downstream_queue(&worker, &flow, payload, 50U, 0U, 0U, false);
    udp_downstream_queue(&worker, &flow, payload, 0U, 0U, 0U, false);
    udp_downstream_flush(&worker);
    assert(saw_gso && !worker.public_gso_enabled);
    assert(mmsg_calls == 2U && msg_calls == 0U && delivered == 5U);
    assert(lengths[0] == 1200U && lengths[1] == 1200U && lengths[2] == 100U);
    assert(lengths[3] == 50U && lengths[4] == 0U);

    reset_sender(SEND_OK);
    for (size_t i = 0U; i < 16U; i++)
        udp_downstream_queue(&worker, &flow, payload, 100U, 0U, 0U, false);
    udp_downstream_flush(&worker);
    assert(mmsg_calls == 1U && msg_calls == 0U && delivered == 16U && !saw_gso);

    reset_sender(PARTIAL_BACKPRESSURE);
    for (size_t i = 0U; i < 16U; i++)
        udp_downstream_queue(&worker, &flow, payload, 100U, 0U, 0U, false);
    udp_downstream_flush(&worker);
    assert(mmsg_calls == 2U && msg_calls == 0U && delivered == 1U);

    worker.public_gso_enabled = true;
    reset_sender(PLAIN_FAIL);
    for (size_t i = 0U; i < 2U; i++)
        udp_downstream_queue(&worker, &flow, payload, 100U, 0U, 0U, false);
    udp_downstream_flush(&worker);
    assert(worker.public_gso_enabled && mmsg_calls == 2U && delivered == 1U);

    reset_sender(PARTIAL_GSO_FAIL);
    udp_downstream_queue(&worker, &flow, payload, 50U, 0U, 0U, false);
    udp_downstream_queue(&worker, &flow, payload, sizeof(payload), 1200U, 0U, false);
    udp_downstream_flush(&worker);
    assert(!worker.public_gso_enabled && mmsg_calls == 3U && delivered == 4U);
    assert(lengths[0] == 50U && lengths[1] == 1200U &&
           lengths[2] == 1200U && lengths[3] == 100U);
    assert(msg_calls == 0U && worker.down_count == 0U);
    destroy_worker(&worker);
    return 0;
}
