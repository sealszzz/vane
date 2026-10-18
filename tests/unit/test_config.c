#include "vane/config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *write_temp(const char *text) {
    char *path = strdup("/tmp/vane-config-XXXXXX");
    assert(path != NULL);
    int fd = mkstemp(path);
    assert(fd >= 0);
    ssize_t n = write(fd, text, strlen(text));
    assert(n == (ssize_t)strlen(text));
    close(fd);
    return path;
}

static void test_proxy_protocol_defaults(void) {
    const char *text =
        "{\"listeners\":["
        "{\"address\":\"127.0.0.1:1443\",\"transport\":\"tcp\",\"targets\":["
        "{\"location\":\"127.0.0.1:9000\",\"sni\":[\"a.example\"]},"
        "{\"location\":\"127.0.0.1:9001\",\"proxy_protocol\":false,\"sni\":[\"b.example\"]},"
        "{\"location\":\"127.0.0.1:9002\",\"proxy_protocol\":true}]},"
        "{\"address\":\"127.0.0.1:1443\",\"transport\":\"udp\",\"targets\":["
        "{\"location\":\"127.0.0.1:9100\",\"sni\":[\"a.example\"]},"
        "{\"location\":\"127.0.0.1:9101\",\"proxy_protocol\":false,\"sni\":[\"b.example\"]},"
        "{\"location\":\"127.0.0.1:9102\",\"proxy_protocol\":true}]}]}";
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(vane_config_load(path, &config, &err));
    assert(config.listener_count == 2U);
    for (size_t i = 0; i < 2U; i++) {
        assert(config.listeners[i].target_count == 3U);
        assert(!config.listeners[i].targets[0].proxy_protocol);
        assert(!config.listeners[i].targets[1].proxy_protocol);
        assert(config.listeners[i].targets[2].proxy_protocol);
    }
    vane_config_destroy(&config);
    unlink(path);
    free(path);
}

static void test_embedded_nul_rejected(void) {
    const char *text =
        "{\"listeners\":[{\"address\":\"127.0.0.1:1443\","
        "\"transport\":\"tcp\",\"targets\":[{"
        "\"location\":\"127.0.0.1:9000\","
        "\"proxy_protocol\":false,"
        "\"sni\":[\"good.example\\u0000bad.example\"]}]}]}";
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "embedded NUL") != NULL);
    unlink(path);
    free(path);
}

static void test_json_depth_rejected(void) {
    char text[256];
    size_t pos = 0U;
    for (size_t i = 0; i < 65U; i++) text[pos++] = '[';
    text[pos++] = '0';
    for (size_t i = 0; i < 65U; i++) text[pos++] = ']';
    text[pos] = '\0';
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "nesting depth") != NULL);
    unlink(path);
    free(path);
}


static void test_json_unicode_keys(void) {
    const char *duplicate = "{\"\xC3\xA9\":1,\"\\u00e9\":2}";
    char *path = write_temp(duplicate);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "duplicate key") != NULL);
    unlink(path);
    free(path);

    const char invalid[] = "{\"\xC0\xAF\":1}";
    path = write_temp(invalid);
    memset(&err, 0, sizeof(err));
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "UTF-8") != NULL);
    unlink(path);
    free(path);
}

static void test_drop_proxy_protocol(void) {
    const char *allowed =
        "{\"listeners\":[{\"address\":\"127.0.0.1:1443\",\"transport\":\"tcp\",\"targets\":["
        "{\"location\":\"drop\",\"sni\":[\"none\",\"any\"]}]}]}";
    char *path = write_temp(allowed);
    struct vane_config config;
    struct vane_error err = {0};
    assert(vane_config_load(path, &config, &err));
    assert(!config.listeners[0].targets[0].proxy_protocol);
    vane_config_destroy(&config);
    unlink(path);
    free(path);

    const char *rejected =
        "{\"listeners\":[{\"address\":\"127.0.0.1:1443\",\"transport\":\"udp\",\"targets\":["
        "{\"location\":\"drop\",\"proxy_protocol\":true}]}]}";
    path = write_temp(rejected);
    memset(&err, 0, sizeof(err));
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "drop target cannot enable proxy_protocol") != NULL);
    unlink(path);
    free(path);
}

static void test_runtime_root_rejected(void) {
    const char *text =
        "{\"runtime\":{},\"listeners\":[{\"address\":\"127.0.0.1:1443\","
        "\"transport\":\"tcp\",\"targets\":[{\"location\":\"127.0.0.1:9000\"}]}]}";
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "unknown field 'runtime'") != NULL);
    unlink(path);
    free(path);
}

static void test_duplicate_sni_rejected(void) {
    const char *text =
        "{\"listeners\":[{\"address\":\"127.0.0.1:1443\",\"transport\":\"tcp\",\"targets\":["
        "{\"location\":\"127.0.0.1:9000\",\"sni\":[\"Dup.Example\"]},"
        "{\"location\":\"127.0.0.1:9001\",\"sni\":[\"dup.example.\"]}]}]}";
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "duplicate SNI routing rule") != NULL);
    unlink(path);
    free(path);
}

static void test_mapped_listener_rejected(void) {
    const char *text =
        "{\"listeners\":[{\"address\":\"[::ffff:127.0.0.1]:1443\","
        "\"transport\":\"udp\",\"targets\":[{\"location\":\"drop\"}]}]}";
    char *path = write_temp(text);
    struct vane_config config;
    struct vane_error err = {0};
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "IPv4-mapped") != NULL);
    unlink(path);
    free(path);
}

int main(void) {
    struct vane_config defaults;
    vane_config_defaults(&defaults);
    assert(defaults.runtime.workers >= 1U);
    assert(defaults.runtime.workers <= VANE_MAX_WORKERS);
    assert(defaults.runtime.tcp_relay_buffer_bytes == 16U * 1024U);
    assert(defaults.runtime.tcp_half_close_idle_timeout_ms == 120000U);
    assert(defaults.runtime.udp_flow_capacity == 4096U);
    assert(defaults.runtime.udp_flow_quiescent_after_ms == 180000U);
    assert(defaults.runtime.udp_flow_hard_idle_timeout_ms == 86400000U);

    const char *good = "{\"listeners\":[{\"address\":\"[::]:443\",\"transport\":\"tcp\",\"targets\":[{\"location\":\"drop\",\"sni\":[\"none\",\"any\"]},{\"location\":\"[::1]:9000\"}]}]}";
    char *path = write_temp(good);
    struct vane_config config;
    struct vane_error err = {0};
    assert(vane_config_load(path, &config, &err));
    assert(config.listener_count == 1U);
    assert(config.listeners[0].target_count == 2U);
    assert(!config.listeners[0].targets[0].proxy_protocol);
    assert(!config.listeners[0].targets[1].proxy_protocol);
    vane_config_destroy(&config);
    unlink(path);
    free(path);

    test_proxy_protocol_defaults();
    test_drop_proxy_protocol();
    test_runtime_root_rejected();
    test_duplicate_sni_rejected();
    test_embedded_nul_rejected();
    test_json_depth_rejected();
    test_json_unicode_keys();
    test_mapped_listener_rejected();

    const char *duplicate = "{\"listeners\":[],\"listeners\":[]}";
    path = write_temp(duplicate);
    assert(!vane_config_load(path, &config, &err));
    assert(strstr(err.message, "duplicate key") != NULL);
    unlink(path);
    free(path);
    return 0;
}
