#include "vane/config.h"
#include "json_validate.h"

#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


static const char *const root_fields[] = {"logging", "listeners"};
static const char *const logging_fields[] = {"level"};
static const char *const listener_fields[] = {"transport", "address", "targets"};
static const char *const target_fields[] = {"location", "sni", "proxy_protocol"};

static bool key_allowed(const char *key, const char *const *allowed, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(key, allowed[i]) == 0) return true;
    }
    return false;
}

static bool reject_unknown(json_object *obj, const char *where,
                           const char *const *allowed, size_t count,
                           struct vane_error *err) {
    struct json_object_iterator it = json_object_iter_begin(obj);
    struct json_object_iterator end = json_object_iter_end(obj);
    while (!json_object_iter_equal(&it, &end)) {
        const char *key = json_object_iter_peek_name(&it);
        if (!key_allowed(key, allowed, count)) {
            vane_error_set(err, "%s contains unknown field '%s'", where, key);
            return false;
        }
        json_object_iter_next(&it);
    }
    return true;
}

static bool object_get(json_object *obj, const char *key, json_type type,
                       bool required, json_object **out,
                       const char *where, struct vane_error *err) {
    json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value)) {
        if (required) vane_error_set(err, "%s is missing required field '%s'", where, key);
        *out = NULL;
        return !required;
    }
    if (json_object_get_type(value) != type) {
        vane_error_set(err, "%s.%s has wrong JSON type", where, key);
        return false;
    }
    *out = value;
    return true;
}

static const char *json_string_value(json_object *value, const char *where,
                                     struct vane_error *err) {
    if (value == NULL || json_object_get_type(value) != json_type_string) {
        vane_error_set(err, "%s must be a string", where);
        return NULL;
    }
    const char *text = json_object_get_string(value);
    size_t length = (size_t)json_object_get_string_len(value);
    if (text == NULL || memchr(text, '\0', length) != NULL) {
        vane_error_set(err, "%s must not contain an embedded NUL", where);
        return NULL;
    }
    return text;
}

static bool parse_log_level(const char *s, enum vane_log_level *out) {
    if (strcmp(s, "error") == 0) *out = VANE_LOG_ERROR;
    else if (strcmp(s, "warn") == 0) *out = VANE_LOG_WARN;
    else if (strcmp(s, "info") == 0) *out = VANE_LOG_INFO;
    else if (strcmp(s, "debug") == 0) *out = VANE_LOG_DEBUG;
    else if (strcmp(s, "trace") == 0) *out = VANE_LOG_TRACE;
    else return false;
    return true;
}

void vane_config_defaults(struct vane_config *config) {
    memset(config, 0, sizeof(*config));
    config->log_level = VANE_LOG_INFO;
    config->runtime.workers = vane_available_cpu_count();
    config->runtime.tcp_max_connections = 4096U;
    config->runtime.tcp_max_connecting = 512U;
    config->runtime.tcp_listen_backlog = 4096U;
    config->runtime.tcp_relay_buffer_bytes = 16U * 1024U;
    config->runtime.tcp_keepalive_idle_secs = 0;
    config->runtime.tcp_keepalive_interval_secs = 0;
    config->runtime.udp_flow_capacity = 4096U;
    config->runtime.udp_max_pending_probes = 1024U;
    config->runtime.tcp_probe_buffer_bytes = VANE_TLS_HANDSHAKE_MAX_SIZE;
    config->runtime.tcp_probe_timeout_ms = 1000U;
    config->runtime.tcp_connect_timeout_ms = 1500U;
    config->runtime.tcp_half_close_idle_timeout_ms = 120000U;
    config->runtime.udp_probe_timeout_ms = 1000U;
    config->runtime.udp_unconfirmed_idle_timeout_ms = 8000U;
    config->runtime.udp_flow_quiescent_after_ms = 180000U;
    config->runtime.udp_flow_hard_idle_timeout_ms = 24U * 60U * 60U * 1000U;
    config->runtime.udp_probe_max_datagrams = 8U;
    config->runtime.udp_probe_max_bytes = 32U * 1024U;
    config->runtime.socket_recv_buffer_bytes = 4U * 1024U * 1024U;
    config->runtime.socket_send_buffer_bytes = 2U * 1024U * 1024U;
    config->runtime.upstream_recv_buffer_bytes = 256U * 1024U;
    config->runtime.upstream_send_buffer_bytes = 256U * 1024U;
    config->runtime.recv_batch = 16U;
    config->runtime.send_batch = 16U;
}

static void target_destroy(struct vane_target_config *target) {
    if (target == NULL) return;
    for (size_t i = 0; i < target->sni_count; i++) free(target->sni[i].hostname);
    free(target->sni);
    memset(target, 0, sizeof(*target));
}

void vane_config_destroy(struct vane_config *config) {
    if (config == NULL) return;
    for (size_t i = 0; i < config->listener_count; i++) {
        struct vane_listener_config *listener = &config->listeners[i];
        for (size_t j = 0; j < listener->target_count; j++) target_destroy(&listener->targets[j]);
        free(listener->targets);
    }
    free(config->listeners);
    memset(config, 0, sizeof(*config));
}

static bool valid_hostname(const char *s, bool wildcard, struct vane_error *err) {
    size_t n = strlen(s);
    if (n == 0 || n > VANE_MAX_SNI_LEN) {
        vane_error_set(err, "SNI hostname length is invalid: '%s'", s);
        return false;
    }
    const char *host = wildcard ? s + 2 : s;
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len > VANE_MAX_SNI_LEN) {
        vane_error_set(err, "SNI wildcard is invalid: '%s'", s);
        return false;
    }
    size_t label_len = 0;
    for (size_t i = 0; i < host_len; i++) {
        unsigned char c = (unsigned char)host[i];
        if (c == '.') {
            if (label_len == 0 || label_len > 63U) {
                vane_error_set(err, "SNI hostname has invalid label: '%s'", s);
                return false;
            }
            label_len = 0;
            continue;
        }
        if (!(isalnum(c) || c == '-' || c == '_')) {
            vane_error_set(err, "SNI hostname contains invalid character: '%s'", s);
            return false;
        }
        label_len++;
    }
    if (label_len == 0 || label_len > 63U) {
        vane_error_set(err, "SNI hostname has invalid final label: '%s'", s);
        return false;
    }
    return true;
}

static char *lower_trim_hostname(const char *raw) {
    while (*raw != '\0' && isspace((unsigned char)*raw)) raw++;
    size_t len = strlen(raw);
    while (len > 0 && isspace((unsigned char)raw[len - 1])) len--;
    while (len > 0 && raw[len - 1] == '.') len--;
    char *s = malloc(len + 1U);
    if (s == NULL) return NULL;
    for (size_t i = 0; i < len; i++) s[i] = (char)tolower((unsigned char)raw[i]);
    s[len] = '\0';
    return s;
}

static bool parse_sni(json_object *array, struct vane_target_config *target,
                      const char *where, struct vane_error *err) {
    size_t count = json_object_array_length(array);
    if (count == 0) {
        vane_error_set(err, "%s.sni must not be empty", where);
        return false;
    }
    target->sni = calloc(count, sizeof(*target->sni));
    if (target->sni == NULL) {
        vane_error_set(err, "out of memory");
        return false;
    }
    target->sni_count = count;
    for (size_t i = 0; i < count; i++) {
        json_object *v = json_object_array_get_idx(array, i);
        if (json_object_get_type(v) != json_type_string) {
            vane_error_set(err, "%s.sni[%zu] must be a string", where, i);
            return false;
        }
        char item_where[160];
        (void)snprintf(item_where, sizeof(item_where), "%s.sni[%zu]", where, i);
        const char *raw = json_string_value(v, item_where, err);
        if (raw == NULL) return false;
        char *s = lower_trim_hostname(raw);
        if (s == NULL) {
            vane_error_set(err, "out of memory");
            return false;
        }
        struct vane_sni_rule *rule = &target->sni[i];
        if (strcmp(s, "none") == 0) {
            rule->kind = VANE_SNI_NONE;
            free(s);
        } else if (strcmp(s, "any") == 0 || strcmp(s, "*") == 0) {
            rule->kind = VANE_SNI_ANY;
            free(s);
        } else if (strncmp(s, "*.", 2) == 0) {
            if (!valid_hostname(s, true, err)) { free(s); return false; }
            rule->kind = VANE_SNI_WILDCARD;
            memmove(s, s + 2, strlen(s + 2) + 1U);
            rule->hostname = s;
        } else {
            if (!valid_hostname(s, false, err)) { free(s); return false; }
            rule->kind = VANE_SNI_EXACT;
            rule->hostname = s;
        }
    }
    return true;
}

static bool parse_target(json_object *obj, struct vane_target_config *target,
                         const char *where, struct vane_error *err) {
    target->proxy_protocol = false;
    if (!reject_unknown(obj, where, target_fields, VANE_ARRAY_LEN(target_fields), err)) return false;
    json_object *location = NULL;
    if (!object_get(obj, "location", json_type_string, true, &location, where, err)) return false;
    char location_where[128];
    (void)snprintf(location_where, sizeof(location_where), "%s.location", where);
    const char *loc = json_string_value(location, location_where, err);
    if (loc == NULL) return false;
    if (strcasecmp(loc, "drop") == 0) {
        target->location_kind = VANE_LOCATION_DROP;
    } else {
        target->location_kind = VANE_LOCATION_ADDRESS;
        if (!vane_addr_parse(loc, false, &target->location, err)) return false;
    }
    json_object *proxy = NULL;
    if (json_object_object_get_ex(obj, "proxy_protocol", &proxy)) {
        if (json_object_get_type(proxy) != json_type_boolean) {
            vane_error_set(err, "%s.proxy_protocol must be boolean", where);
            return false;
        }
        target->proxy_protocol = json_object_get_boolean(proxy) != 0;
    }
    if (target->location_kind == VANE_LOCATION_DROP && target->proxy_protocol) {
        vane_error_set(err, "%s drop target cannot enable proxy_protocol", where);
        return false;
    }
    json_object *sni = NULL;
    if (json_object_object_get_ex(obj, "sni", &sni)) {
        if (json_object_get_type(sni) != json_type_array) {
            vane_error_set(err, "%s.sni must be an array", where);
            return false;
        }
        if (!parse_sni(sni, target, where, err)) {
            target_destroy(target);
            return false;
        }
    }
    return true;
}

struct sni_ref {
    enum vane_sni_kind kind;
    const char *hostname;
};

static int sni_ref_compare(const void *a, const void *b) {
    const struct sni_ref *ra = a;
    const struct sni_ref *rb = b;
    if (ra->kind < rb->kind) return -1;
    if (ra->kind > rb->kind) return 1;
    if (ra->hostname == NULL) return rb->hostname == NULL ? 0 : -1;
    if (rb->hostname == NULL) return 1;
    return strcmp(ra->hostname, rb->hostname);
}

static bool validate_listener_routes(const struct vane_listener_config *listener,
                                     const char *where,
                                     struct vane_error *err) {
    size_t fallback_count = 0U;
    size_t rule_count = 0U;
    for (size_t i = 0; i < listener->target_count; i++) {
        const struct vane_target_config *target = &listener->targets[i];
        if (target->sni_count == 0U) fallback_count++;
        if (target->sni_count > SIZE_MAX - rule_count) {
            vane_error_set(err, "%s has too many SNI rules", where);
            return false;
        }
        rule_count += target->sni_count;
    }
    if (fallback_count > 1U) {
        vane_error_set(err, "%s defines duplicate fallback routes", where);
        return false;
    }
    if (rule_count == 0U) return true;
    if (rule_count > SIZE_MAX / sizeof(struct sni_ref)) {
        vane_error_set(err, "%s has too many SNI rules", where);
        return false;
    }
    struct sni_ref *refs = malloc(rule_count * sizeof(*refs));
    if (refs == NULL) {
        vane_error_set(err, "out of memory");
        return false;
    }
    size_t n = 0U;
    for (size_t i = 0; i < listener->target_count; i++) {
        const struct vane_target_config *target = &listener->targets[i];
        for (size_t j = 0; j < target->sni_count; j++) {
            refs[n++] = (struct sni_ref){
                .kind = target->sni[j].kind,
                .hostname = target->sni[j].hostname,
            };
        }
    }
    qsort(refs, rule_count, sizeof(*refs), sni_ref_compare);
    bool valid = true;
    for (size_t i = 1U; i < rule_count; i++) {
        if (sni_ref_compare(&refs[i - 1U], &refs[i]) == 0) {
            vane_error_set(err, "%s defines duplicate SNI routing rule", where);
            valid = false;
            break;
        }
    }
    free(refs);
    return valid;
}

static bool parse_listener(json_object *obj, struct vane_listener_config *listener,
                           size_t index, struct vane_error *err) {
    char where[64];
    (void)snprintf(where, sizeof(where), "listeners[%zu]", index);
    if (!reject_unknown(obj, where, listener_fields, VANE_ARRAY_LEN(listener_fields), err)) return false;
    json_object *address = NULL, *transport = NULL, *targets = NULL;
    if (!object_get(obj, "address", json_type_string, true, &address, where, err) ||
        !object_get(obj, "transport", json_type_string, true, &transport, where, err) ||
        !object_get(obj, "targets", json_type_array, true, &targets, where, err)) return false;
    char address_where[128];
    char transport_where[128];
    (void)snprintf(address_where, sizeof(address_where), "%s.address", where);
    (void)snprintf(transport_where, sizeof(transport_where), "%s.transport", where);
    const char *address_text = json_string_value(address, address_where, err);
    const char *tr = json_string_value(transport, transport_where, err);
    if (address_text == NULL || tr == NULL ||
        !vane_addr_parse(address_text, false, &listener->address, err)) return false;
    if (listener->address.storage.ss_family == AF_INET6 &&
        vane_addr_effective_family(&listener->address) == AF_INET) {
        vane_error_set(err, "%s.address must use IPv4 notation instead of an IPv4-mapped IPv6 listener", where);
        return false;
    }
    if (strcmp(tr, "tcp") == 0) listener->transport = VANE_TRANSPORT_TCP;
    else if (strcmp(tr, "udp") == 0) listener->transport = VANE_TRANSPORT_UDP;
    else {
        vane_error_set(err, "%s.transport must be 'tcp' or 'udp'", where);
        return false;
    }
    size_t count = json_object_array_length(targets);
    if (count == 0 || count > VANE_MAX_TARGETS) {
        vane_error_set(err, "%s.targets count is invalid", where);
        return false;
    }
    listener->targets = calloc(count, sizeof(*listener->targets));
    if (listener->targets == NULL) { vane_error_set(err, "out of memory"); return false; }
    listener->target_count = count;
    for (size_t i = 0; i < count; i++) {
        json_object *target_obj = json_object_array_get_idx(targets, i);
        if (json_object_get_type(target_obj) != json_type_object) {
            vane_error_set(err, "%s.targets[%zu] must be an object", where, i);
            return false;
        }
        char target_where[96];
        (void)snprintf(target_where, sizeof(target_where), "%s.targets[%zu]", where, i);
        if (!parse_target(target_obj, &listener->targets[i], target_where, err)) return false;
    }
    return validate_listener_routes(listener, where, err);
}

static bool validate_listener_overlap(const struct vane_config *cfg,
                                      struct vane_error *err) {
    for (size_t i = 0; i < cfg->listener_count; i++) {
        for (size_t j = i + 1; j < cfg->listener_count; j++) {
            const struct vane_listener_config *a = &cfg->listeners[i];
            const struct vane_listener_config *b = &cfg->listeners[j];
            if (a->transport != b->transport || vane_addr_port(&a->address) != vane_addr_port(&b->address)) continue;
            bool overlap = vane_addr_equal(&a->address, &b->address);
            if (!overlap && vane_addr_is_wildcard(&a->address) &&
                a->address.storage.ss_family == b->address.storage.ss_family) overlap = true;
            if (!overlap && vane_addr_is_wildcard(&b->address) &&
                a->address.storage.ss_family == b->address.storage.ss_family) overlap = true;
            if (!overlap && (vane_addr_is_dual_stack_wildcard(&a->address) ||
                             vane_addr_is_dual_stack_wildcard(&b->address))) overlap = true;
            if (overlap) {
                char abuf[96], bbuf[96];
                vane_error_set(err, "overlapping %s listeners: %s and %s",
                                 a->transport == VANE_TRANSPORT_TCP ? "TCP" : "UDP",
                                 vane_addr_format(&a->address, abuf, sizeof(abuf)),
                                 vane_addr_format(&b->address, bbuf, sizeof(bbuf)));
                return false;
            }
        }
    }
    return true;
}

bool vane_config_load(const char *path, struct vane_config *out,
                        struct vane_error *err) {
    vane_config_defaults(out);
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        vane_error_set(err, "cannot open config %s: %s", path, strerror(errno));
        return false;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); vane_error_set(err, "cannot seek config"); return false; }
    long file_len = ftell(fp);
    if (file_len < 0 || file_len > 16L * 1024L * 1024L) { fclose(fp); vane_error_set(err, "config size is invalid"); return false; }
    rewind(fp);
    char *text = malloc((size_t)file_len + 1U);
    if (text == NULL) { fclose(fp); vane_error_set(err, "out of memory"); return false; }
    size_t nread = fread(text, 1, (size_t)file_len, fp);
    fclose(fp);
    if (nread != (size_t)file_len) { free(text); vane_error_set(err, "short read from config"); return false; }
    text[nread] = '\0';
    if (!vane_json_validate_strict(text, nread, err)) { free(text); return false; }

    struct json_tokener *tok = json_tokener_new_ex(64);
    if (tok == NULL) { free(text); vane_error_set(err, "out of memory"); return false; }
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    json_object *root = json_tokener_parse_ex(tok, text, (int)nread);
    enum json_tokener_error jerr = json_tokener_get_error(tok);
    json_tokener_free(tok);
    free(text);
    if (root == NULL || jerr != json_tokener_success || json_object_get_type(root) != json_type_object) {
        if (root != NULL) json_object_put(root);
        vane_error_set(err, "config root must be a JSON object");
        return false;
    }
    bool ok = reject_unknown(root, "config", root_fields, VANE_ARRAY_LEN(root_fields), err);
    json_object *logging = NULL;
    if (ok && json_object_object_get_ex(root, "logging", &logging)) {
        ok = json_object_get_type(logging) == json_type_object;
        if (!ok) vane_error_set(err, "logging must be an object");
        if (ok) ok = reject_unknown(logging, "logging", logging_fields, VANE_ARRAY_LEN(logging_fields), err);
        json_object *level = NULL;
        if (ok && json_object_object_get_ex(logging, "level", &level)) {
            const char *level_text = json_string_value(level, "logging.level", err);
            if (level_text == NULL || !parse_log_level(level_text, &out->log_level)) {
                if (level_text != NULL)
                    vane_error_set(err, "logging.level must be error|warn|info|debug|trace");
                ok = false;
            }
        }
    }
    json_object *listeners = NULL;
    if (ok) ok = object_get(root, "listeners", json_type_array, true, &listeners, "config", err);
    if (ok) {
        size_t count = json_object_array_length(listeners);
        if (count == 0 || count > VANE_MAX_LISTENERS) {
            vane_error_set(err, "listeners count must be 1..%u", VANE_MAX_LISTENERS);
            ok = false;
        } else {
            out->listeners = calloc(count, sizeof(*out->listeners));
            if (out->listeners == NULL) { vane_error_set(err, "out of memory"); ok = false; }
            else out->listener_count = count;
            for (size_t i = 0; ok && i < count; i++) {
                json_object *obj = json_object_array_get_idx(listeners, i);
                if (json_object_get_type(obj) != json_type_object) {
                    vane_error_set(err, "listeners[%zu] must be an object", i);
                    ok = false;
                } else ok = parse_listener(obj, &out->listeners[i], i, err);
            }
        }
    }
    if (ok) {
        size_t tcp_listeners = 0U, udp_listeners = 0U;
        for (size_t i = 0; i < out->listener_count; i++) {
            if (out->listeners[i].transport == VANE_TRANSPORT_TCP) tcp_listeners++;
            else udp_listeners++;
        }
        size_t available = vane_available_cpu_count();
        size_t per_listener = available / out->listener_count;
        if (per_listener == 0U) per_listener = 1U;
        if (tcp_listeners != 0U) {
            per_listener = VANE_MIN(per_listener,
                out->runtime.tcp_max_connections / tcp_listeners);
            per_listener = VANE_MIN(per_listener,
                out->runtime.tcp_max_connecting / tcp_listeners);
        }
        if (udp_listeners != 0U) {
            per_listener = VANE_MIN(per_listener,
                out->runtime.udp_flow_capacity / udp_listeners);
            per_listener = VANE_MIN(per_listener,
                out->runtime.udp_max_pending_probes / udp_listeners);
        }
        out->runtime.workers = per_listener == 0U ? 1U : per_listener;
    }
    if (ok && (out->runtime.tcp_probe_buffer_bytes < 5U ||
               out->runtime.tcp_probe_buffer_bytes > VANE_TLS_HANDSHAKE_MAX_SIZE)) {
        vane_error_set(err, "internal tcp_probe_buffer_bytes must be 5..%u",
                         VANE_TLS_HANDSHAKE_MAX_SIZE);
        ok = false;
    }
    if (ok && (out->runtime.recv_batch > 256U || out->runtime.send_batch > 256U)) {
        vane_error_set(err, "internal recv_batch/send_batch must not exceed 256");
        ok = false;
    }
    if (ok && out->runtime.tcp_max_connecting > out->runtime.tcp_max_connections)
        out->runtime.tcp_max_connecting = out->runtime.tcp_max_connections;
    if (ok && out->runtime.udp_max_pending_probes > out->runtime.udp_flow_capacity)
        out->runtime.udp_max_pending_probes = out->runtime.udp_flow_capacity;
    if (ok && out->runtime.udp_flow_quiescent_after_ms >=
              out->runtime.udp_flow_hard_idle_timeout_ms) {
        vane_error_set(err,
            "internal UDP quiescent timeout must be less than hard idle timeout");
        ok = false;
    }
    if (ok && (out->runtime.socket_recv_buffer_bytes > (size_t)INT_MAX ||
               out->runtime.socket_send_buffer_bytes > (size_t)INT_MAX ||
               out->runtime.upstream_recv_buffer_bytes > (size_t)INT_MAX ||
               out->runtime.upstream_send_buffer_bytes > (size_t)INT_MAX)) {
        vane_error_set(err, "internal socket buffer value exceeds INT_MAX");
        ok = false;
    }
    if (ok && (out->runtime.tcp_listen_backlog > (size_t)INT_MAX ||
               out->runtime.tcp_relay_buffer_bytes < 4096U ||
               out->runtime.tcp_relay_buffer_bytes > 4U * 1024U * 1024U)) {
        vane_error_set(err, "internal TCP backlog/buffer value is outside the supported range");
        ok = false;
    }
    if (ok && (out->runtime.udp_probe_max_datagrams > 64U ||
               out->runtime.udp_probe_max_bytes > VANE_TLS_HANDSHAKE_MAX_SIZE)) {
        vane_error_set(err, "internal UDP probe limits exceed parser bounds");
        ok = false;
    }
    if (ok) {
        size_t tcp_listeners = 0U, udp_listeners = 0U;
        for (size_t i = 0; i < out->listener_count; i++) {
            if (out->listeners[i].transport == VANE_TRANSPORT_TCP) tcp_listeners++;
            else udp_listeners++;
        }
        if ((tcp_listeners != 0U &&
             (tcp_listeners > SIZE_MAX / out->runtime.workers ||
              out->runtime.tcp_max_connections < tcp_listeners * out->runtime.workers ||
              out->runtime.tcp_max_connecting < tcp_listeners * out->runtime.workers)) ||
            (udp_listeners != 0U &&
             (udp_listeners > SIZE_MAX / out->runtime.workers ||
              out->runtime.udp_flow_capacity < udp_listeners * out->runtime.workers ||
              out->runtime.udp_max_pending_probes < udp_listeners * out->runtime.workers))) {
            vane_error_set(err,
                "internal limits must provide at least one slot per listener worker");
            ok = false;
        }
        if (ok && tcp_listeners != 0U) {
            size_t shards = tcp_listeners * out->runtime.workers;
            size_t max_connections = out->runtime.tcp_max_connections / shards +
                (out->runtime.tcp_max_connections % shards != 0U ? 1U : 0U);
            if (max_connections > 0x00ffffffU) {
                vane_error_set(err,
                    "internal TCP capacity exceeds the per-worker event ID range");
                ok = false;
            }
        }
        if (ok && udp_listeners != 0U) {
            size_t shards = udp_listeners * out->runtime.workers;
            size_t max_flows = out->runtime.udp_flow_capacity / shards +
                (out->runtime.udp_flow_capacity % shards != 0U ? 1U : 0U);
            size_t max_pending = out->runtime.udp_max_pending_probes / shards +
                (out->runtime.udp_max_pending_probes % shards != 0U ? 1U : 0U);
            if (max_flows > 0x00ffffffU / 2U ||
                max_pending > (size_t)UINT32_MAX) {
                vane_error_set(err,
                    "internal UDP capacity exceeds the per-worker burst ID range");
                ok = false;
            }
        }
    }
    if (ok) ok = validate_listener_overlap(out, err);
    json_object_put(root);
    if (!ok) vane_config_destroy(out);
    return ok;
}
