#include "vane/proxy_protocol.h"

#include <assert.h>
#include <string.h>

int main(void) {
    struct vane_addr src, dst;
    struct vane_error err = {0};
    assert(vane_addr_parse("192.0.2.1:12345", false, &src, &err));
    assert(vane_addr_parse("198.51.100.2:443", false, &dst, &err));
    struct vane_proxy_header h;
    assert(vane_proxy_v2_encode(&src, &dst, VANE_PROXY_STREAM, &h, &err));
    assert(h.len == 28);
    assert(h.bytes[12] == 0x21 && h.bytes[13] == 0x11);
    assert(memcmp(h.bytes, "\r\n\r\n\0\r\nQUIT\n", 12) == 0);
    return 0;
}
