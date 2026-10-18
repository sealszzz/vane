#include <arpa/inet.h>
#include <errno.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

static int unsupported_errno(int value) {
    return value == EINVAL || value == ENOPROTOOPT ||
           value == EOPNOTSUPP || value == ENOSYS;
}

int main(void) {
    int receiver = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    int sender = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    if (receiver < 0 || sender < 0) {
        perror("socket");
        if (receiver >= 0) close(receiver);
        if (sender >= 0) close(sender);
        return 1;
    }

    int result = 1;
    int on = 1;
    if (setsockopt(receiver, SOL_UDP, UDP_GRO, &on, sizeof(on)) != 0) {
        if (unsupported_errno(errno)) {
            (void)printf("udp_offload=unsupported stage=UDP_GRO errno=%d\n", errno);
            result = 77;
            goto done;
        }
        perror("setsockopt UDP_GRO");
        result = 2;
        goto done;
    }

    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (bind(receiver, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind");
        result = 3;
        goto done;
    }
    socklen_t address_len = sizeof(address);
    if (getsockname(receiver, (struct sockaddr *)&address, &address_len) != 0 ||
        connect(sender, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect");
        result = 4;
        goto done;
    }

    enum { SEGMENT_SIZE = 1372, SEGMENTS = 4 };
    uint8_t payload[SEGMENT_SIZE * SEGMENTS];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i / SEGMENT_SIZE + 1U);

    struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
    union {
        struct cmsghdr align;
        uint8_t bytes[CMSG_SPACE(sizeof(uint16_t))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL) {
        result = 5;
        goto done;
    }
    cmsg->cmsg_level = SOL_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t segment_size = SEGMENT_SIZE;
    memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));

    ssize_t sent = sendmsg(sender, &message, 0);
    if (sent < 0) {
        if (unsupported_errno(errno)) {
            (void)printf("udp_offload=unsupported stage=UDP_SEGMENT errno=%d\n", errno);
            result = 77;
            goto done;
        }
        perror("sendmsg UDP_SEGMENT");
        result = 6;
        goto done;
    }

    uint8_t received[64U * 1024U];
    union {
        struct cmsghdr align;
        uint8_t bytes[256];
    } received_control;
    memset(&received_control, 0, sizeof(received_control));
    struct iovec received_iov = {.iov_base = received, .iov_len = sizeof(received)};
    struct msghdr received_message;
    memset(&received_message, 0, sizeof(received_message));
    received_message.msg_iov = &received_iov;
    received_message.msg_iovlen = 1;
    received_message.msg_control = received_control.bytes;
    received_message.msg_controllen = sizeof(received_control.bytes);
    ssize_t received_len = recvmsg(receiver, &received_message, 0);
    if (received_len < 0) {
        perror("recvmsg");
        result = 7;
        goto done;
    }

    int gro_segment_size = 0;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&received_message);
         item != NULL; item = CMSG_NXTHDR(&received_message, item)) {
        if (item->cmsg_level == SOL_UDP && item->cmsg_type == UDP_GRO) {
            size_t data_len = item->cmsg_len - CMSG_LEN(0);
            if (data_len >= sizeof(int)) {
                memcpy(&gro_segment_size, CMSG_DATA(item), sizeof(gro_segment_size));
            } else if (data_len >= sizeof(uint16_t)) {
                uint16_t value = 0;
                memcpy(&value, CMSG_DATA(item), sizeof(value));
                gro_segment_size = value;
            }
        }
    }

    (void)printf("udp_offload=ok sent=%zd received=%zd gro_segment=%d segments=%zd\n",
                 sent, received_len, gro_segment_size,
                 gro_segment_size > 0
                     ? (received_len + gro_segment_size - 1) / gro_segment_size
                     : 1);
    result = !(sent == (ssize_t)sizeof(payload) &&
               received_len == (ssize_t)sizeof(payload) &&
               gro_segment_size == SEGMENT_SIZE &&
               memcmp(payload, received, sizeof(payload)) == 0);

done:
    close(receiver);
    close(sender);
    return result;
}
