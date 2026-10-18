#include "vane/address.h"
#include "vane/linux_net.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void bind_loopback4(int fd, struct vane_addr *out) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
    socklen_t len = (socklen_t)sizeof(addr);
    assert(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&addr, len, out));
}

static void test_ipv4_connected_tclass(void) {
    int server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(server >= 0 && client >= 0);

    struct vane_addr server_addr;
    bind_loopback4(server, &server_addr);
    assert(connect(client, (const struct sockaddr *)&server_addr.storage,
                   server_addr.len) == 0);

    const unsigned char payload[] = {0x01, 0x02, 0x03, 0x04};
    struct iovec iov = {.iov_base = (void *)(uintptr_t)payload, .iov_len = sizeof(payload)};
    uint8_t tclass = 0x02U;
    struct vane_error err = {0};
    ssize_t sent = vane_udp_sendmsg(client, AF_INET, &iov, 1, NULL, NULL,
                                      &tclass, NULL, &err);
    assert(sent == (ssize_t)sizeof(payload));

    unsigned char received[sizeof(payload)];
    ssize_t n = recv(server, received, sizeof(received), 0);
    assert(n == (ssize_t)sizeof(received));
    assert(memcmp(received, payload, sizeof(payload)) == 0);

    close(client);
    close(server);
}

static void test_dual_stack_ipv4_metadata_roundtrip(void) {
    int server = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(server >= 0 && client >= 0);

    int zero = 0;
    assert(setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &zero,
                      (socklen_t)sizeof(zero)) == 0);
    struct sockaddr_in6 bound6 = {0};
    bound6.sin6_family = AF_INET6;
    bound6.sin6_addr = in6addr_any;
    assert(bind(server, (const struct sockaddr *)&bound6, sizeof(bound6)) == 0);
    socklen_t bound6_len = (socklen_t)sizeof(bound6);
    assert(getsockname(server, (struct sockaddr *)&bound6, &bound6_len) == 0);

    struct vane_addr server_bound;
    assert(vane_addr_from_sockaddr((const struct sockaddr *)&bound6,
                                     bound6_len, &server_bound));
    struct vane_error err = {0};
    assert(vane_udp_enable_metadata(server, AF_INET6, false, &err) == 0);

    struct vane_addr client_bound;
    bind_loopback4(client, &client_bound);
    memset(&err, 0, sizeof(err));
    assert(vane_udp_enable_metadata(client, AF_INET, false, &err) == 0);

    int tos = 0x02;
    assert(setsockopt(client, IPPROTO_IP, IP_TOS, &tos,
                      (socklen_t)sizeof(tos)) == 0);
    struct sockaddr_in destination = {0};
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    destination.sin_port = bound6.sin6_port;
    const unsigned char request[] = "dual-stack-request";
    assert(sendto(client, request, sizeof(request), 0,
                  (const struct sockaddr *)&destination, sizeof(destination)) ==
           (ssize_t)sizeof(request));

    unsigned char input[128];
    struct vane_udp_meta incoming;
    memset(&err, 0, sizeof(err));
    ssize_t n = vane_udp_recvmsg(server, input, sizeof(input), &server_bound,
                                   &incoming, &err);
    assert(n == (ssize_t)sizeof(request));
    assert(incoming.has_tclass && incoming.tclass == (uint8_t)tos);
    assert(vane_addr_effective_family(&incoming.peer) == AF_INET);
    assert(vane_addr_effective_family(&incoming.local) == AF_INET);

    const unsigned char response[] = "dual-stack-response";
    struct iovec iov = {
        .iov_base = (void *)(uintptr_t)response,
        .iov_len = sizeof(response),
    };
    memset(&err, 0, sizeof(err));
    assert(vane_udp_sendmsg(server, AF_INET, &iov, 1, &incoming.peer,
                              &incoming.local, &incoming.tclass, NULL, &err) ==
           (ssize_t)sizeof(response));

    struct vane_udp_meta returned;
    unsigned char output[128];
    memset(&err, 0, sizeof(err));
    n = vane_udp_recvmsg(client, output, sizeof(output), &client_bound,
                           &returned, &err);
    assert(n == (ssize_t)sizeof(response));
    assert(memcmp(output, response, sizeof(response)) == 0);
    assert(returned.has_tclass && returned.tclass == (uint8_t)tos);

    close(client);
    close(server);
}

static void test_invalid_family(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    unsigned char byte = 0;
    struct iovec iov = {.iov_base = &byte, .iov_len = 1U};
    uint8_t tclass = 0;
    struct vane_error err = {0};
    errno = 0;
    assert(vane_udp_sendmsg(fd, AF_UNSPEC, &iov, 1, NULL, NULL,
                              &tclass, NULL, &err) == -1);
    assert(errno == EAFNOSUPPORT);
    close(fd);
}

int main(void) {
    test_ipv4_connected_tclass();
    test_dual_stack_ipv4_metadata_roundtrip();
    test_invalid_family();
    return 0;
}
