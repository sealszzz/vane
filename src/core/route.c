#include "vane/route.h"

#include <stdlib.h>
#include <string.h>

struct route_entry {
    const struct vane_target_config *target;
    const char *hostname;
};

struct vane_route_table {
    const struct vane_target_config *fallback;
    const struct vane_target_config *none;
    const struct vane_target_config *any;
    struct route_entry *exact;
    size_t exact_count;
    struct route_entry *wildcards;
    size_t wildcard_count;
    bool has_protocol_rules;
};

static int exact_compare(const void *a, const void *b) {
    const struct route_entry *ra = a;
    const struct route_entry *rb = b;
    return strcmp(ra->hostname, rb->hostname);
}


bool vane_route_table_build(const struct vane_listener_config *listener,
                              struct vane_route_table **out,
                              struct vane_error *err) {
    if (listener == NULL || out == NULL) {
        vane_error_set(err, "route table input is missing");
        return false;
    }
    struct vane_route_table *table = calloc(1, sizeof(*table));
    if (table == NULL) {
        vane_error_set(err, "out of memory");
        return false;
    }
    size_t exact_count = 0, wildcard_count = 0;
    for (size_t i = 0; i < listener->target_count; i++) {
        const struct vane_target_config *target = &listener->targets[i];
        if (target->sni_count == 0) table->fallback = target;
        for (size_t j = 0; j < target->sni_count; j++) {
            table->has_protocol_rules = true;
            if (target->sni[j].kind == VANE_SNI_EXACT) exact_count++;
            if (target->sni[j].kind == VANE_SNI_WILDCARD) wildcard_count++;
        }
    }
    table->exact = calloc(exact_count == 0U ? 1U : exact_count,
                          sizeof(*table->exact));
    table->wildcards = calloc(wildcard_count == 0U ? 1U : wildcard_count,
                              sizeof(*table->wildcards));
    if (table->exact == NULL || table->wildcards == NULL) {
        vane_error_set(err, "out of memory");
        vane_route_table_destroy(table);
        return false;
    }
    for (size_t i = 0; i < listener->target_count; i++) {
        const struct vane_target_config *target = &listener->targets[i];
        for (size_t j = 0; j < target->sni_count; j++) {
            const struct vane_sni_rule *rule = &target->sni[j];
            if (rule->kind == VANE_SNI_NONE) table->none = target;
            else if (rule->kind == VANE_SNI_ANY) table->any = target;
            else if (rule->kind == VANE_SNI_EXACT) {
                struct route_entry *e = &table->exact[table->exact_count++];
                e->target = target;
                e->hostname = rule->hostname;
            } else if (rule->kind == VANE_SNI_WILDCARD) {
                struct route_entry *e = &table->wildcards[table->wildcard_count++];
                e->target = target;
                e->hostname = rule->hostname;
            }
        }
    }
    if (table->exact_count > 1U) {
        qsort(table->exact, table->exact_count, sizeof(*table->exact), exact_compare);
    }
    if (table->wildcard_count > 1U) {
        qsort(table->wildcards, table->wildcard_count, sizeof(*table->wildcards),
              exact_compare);
    }
    *out = table;
    return true;
}

void vane_route_table_destroy(struct vane_route_table *table) {
    if (table == NULL) return;
    free(table->exact);
    free(table->wildcards);
    free(table);
}

static const struct vane_target_config *
find_hostname(const struct route_entry *entries, size_t count,
              const char *hostname) {
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2U;
        int cmp = strcmp(hostname, entries[mid].hostname);
        if (cmp == 0) return entries[mid].target;
        if (cmp < 0) hi = mid;
        else lo = mid + 1U;
    }
    return NULL;
}

const struct vane_target_config *
vane_route_select_tls(const struct vane_route_table *table,
                        const struct vane_client_hello *hello) {
    if (table == NULL || hello == NULL) return NULL;
    if (!hello->has_sni) return table->none != NULL ? table->none : table->any;

    const struct vane_target_config *target =
        find_hostname(table->exact, table->exact_count, hello->server_name);
    if (target != NULL) return target;

    /* Scan candidate suffixes from longest to shortest, then binary-search the
     * wildcard table. This preserves longest-wildcard precedence without a
     * linear scan over every configured wildcard. */
    size_t host_len = hello->server_name_len;
    if (host_len == 0U) host_len = strlen(hello->server_name);
    for (size_t i = 0; i < host_len; i++) {
        if (hello->server_name[i] != '.' || i + 1U >= host_len) continue;
        target = find_hostname(table->wildcards, table->wildcard_count,
                               hello->server_name + i + 1U);
        if (target != NULL) return target;
    }
    return table->any;
}

const struct vane_target_config *
vane_route_select_fallback(const struct vane_route_table *table) {
    return table == NULL ? NULL : table->fallback;
}

bool vane_route_has_protocol_rules(const struct vane_route_table *table) {
    return table != NULL && table->has_protocol_rules;
}
