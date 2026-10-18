#include "vane/route.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void set_rule(struct vane_target_config *target,
                     enum vane_sni_kind kind, const char *hostname) {
    target->sni = calloc(1, sizeof(*target->sni));
    assert(target->sni != NULL);
    target->sni_count = 1;
    target->sni[0].kind = kind;
    if (hostname != NULL) {
        target->sni[0].hostname = strdup(hostname);
        assert(target->sni[0].hostname != NULL);
    }
}


static void set_hello(struct vane_client_hello *hello, const char *hostname) {
    memset(hello, 0, sizeof(*hello));
    hello->has_sni = true;
    hello->server_name_len = strlen(hostname);
    assert(hello->server_name_len <= VANE_MAX_SNI_LEN);
    memcpy(hello->server_name, hostname, hello->server_name_len + 1U);
}

static void destroy_listener(struct vane_listener_config *listener) {
    for (size_t i = 0; i < listener->target_count; i++) {
        for (size_t j = 0; j < listener->targets[i].sni_count; j++) {
            free(listener->targets[i].sni[j].hostname);
        }
        free(listener->targets[i].sni);
    }
    free(listener->targets);
}

static void test_large_rule_set(void) {
    const size_t exact_count = 2048U;
    const size_t wildcard_count = 2048U;
    struct vane_listener_config listener = {0};
    listener.target_count = exact_count + wildcard_count + 1U;
    listener.targets = calloc(listener.target_count, sizeof(*listener.targets));
    assert(listener.targets != NULL);

    char hostname[128];
    for (size_t i = 0; i < exact_count; i++) {
        int n = snprintf(hostname, sizeof(hostname), "host-%04zu.example.net", i);
        assert(n > 0 && (size_t)n < sizeof(hostname));
        set_rule(&listener.targets[i], VANE_SNI_EXACT, hostname);
    }
    for (size_t i = 0; i < wildcard_count; i++) {
        int n = snprintf(hostname, sizeof(hostname), "zone-%04zu.example.org", i);
        assert(n > 0 && (size_t)n < sizeof(hostname));
        set_rule(&listener.targets[exact_count + i], VANE_SNI_WILDCARD, hostname);
    }
    struct vane_target_config *fallback = &listener.targets[listener.target_count - 1U];
    VANE_UNUSED(fallback);

    struct vane_route_table *table = NULL;
    struct vane_error err = {0};
    assert(vane_route_table_build(&listener, &table, &err));
    struct vane_client_hello hello;
    set_hello(&hello, "host-1777.example.net");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[1777U]);
    set_hello(&hello, "deep.zone-1888.example.org");
    assert(vane_route_select_tls(table, &hello) ==
           &listener.targets[exact_count + 1888U]);
    set_hello(&hello, "missing.example.invalid");
    assert(vane_route_select_tls(table, &hello) == NULL);

    vane_route_table_destroy(table);
    destroy_listener(&listener);
}

int main(void) {
    struct vane_listener_config listener = {0};
    listener.target_count = 8;
    listener.targets = calloc(listener.target_count, sizeof(*listener.targets));
    assert(listener.targets != NULL);

    set_rule(&listener.targets[0], VANE_SNI_WILDCARD, "example.com");
    set_rule(&listener.targets[1], VANE_SNI_WILDCARD, "api.example.com");
    set_rule(&listener.targets[2], VANE_SNI_EXACT, "z.example.com");
    set_rule(&listener.targets[3], VANE_SNI_EXACT, "v1.api.example.com");
    set_rule(&listener.targets[4], VANE_SNI_EXACT, "a.example.com");
    set_rule(&listener.targets[5], VANE_SNI_NONE, NULL);
    set_rule(&listener.targets[6], VANE_SNI_ANY, NULL);
    /* targets[7] has no SNI rules and is therefore the fallback. */

    struct vane_route_table *table = NULL;
    struct vane_error err = {0};
    assert(vane_route_table_build(&listener, &table, &err));

    struct vane_client_hello hello;
    set_hello(&hello, "a.example.com");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[4]);
    set_hello(&hello, "v1.api.example.com");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[3]);
    set_hello(&hello, "z.example.com");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[2]);
    set_hello(&hello, "x.api.example.com");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[1]);
    set_hello(&hello, "x.example.com");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[0]);
    set_hello(&hello, "other.invalid");
    assert(vane_route_select_tls(table, &hello) == &listener.targets[6]);

    hello.has_sni = false;
    hello.server_name[0] = '\0';
    assert(vane_route_select_tls(table, &hello) == &listener.targets[5]);
    assert(vane_route_select_fallback(table) == &listener.targets[7]);
    assert(vane_route_has_protocol_rules(table));

    vane_route_table_destroy(table);
    destroy_listener(&listener);
    test_large_rule_set();
    return 0;
}
