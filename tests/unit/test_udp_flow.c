#include "udp_internal.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct vane_runtime_config test_runtime;
static struct vane_worker_args test_args;

static struct udp_flow_key make_key(uint16_t client_port) {
    struct udp_flow_key key = {0};
    struct vane_error err = {0};
    char client[32];
    int n = snprintf(client, sizeof(client), "127.0.0.1:%u",
                     (unsigned)client_port);
    assert(n > 0 && (size_t)n < sizeof(client));
    assert(vane_addr_parse(client, false, &key.client, &err));
    memset(&err, 0, sizeof(err));
    assert(vane_addr_parse("127.0.0.1:443", false, &key.local, &err));
    return key;
}

static size_t key_home(const struct udp_flow_key *key, uint64_t seed,
                       size_t capacity) {
    uint64_t first = vane_addr_hash(&key->client, seed);
    uint64_t hash = vane_addr_hash(
        &key->local, first ^ UINT64_C(0x9e3779b97f4a7c15));
    return (size_t)hash & (capacity - 1U);
}

static void worker_table_init(struct udp_worker *worker, size_t base_limit,
                              size_t flow_capacity, size_t table_capacity) {
    memset(worker, 0, sizeof(*worker));
    memset(&test_runtime, 0, sizeof(test_runtime));
    memset(&test_args, 0, sizeof(test_args));
    test_runtime.udp_probe_timeout_ms = 100U;
    test_runtime.udp_unconfirmed_idle_timeout_ms = 100U;
    test_runtime.udp_flow_quiescent_after_ms = 100U;
    test_runtime.udp_flow_hard_idle_timeout_ms = 100000U;
    test_args.runtime = &test_runtime;
    test_args.worker_index = 0U;

    worker->args = &test_args;
    worker->epoll_fd = -1;
    worker->public_fd = -1;
    worker->flow_base_limit = base_limit;
    worker->flow_limit = base_limit;
    worker->flow_capacity = flow_capacity;
    worker->table_capacity = table_capacity;
    worker->pending_limit = 1U;
    worker->hash_seed = UINT64_C(0x8b8b8b8b12345678);
    worker->flows = calloc(flow_capacity, sizeof(*worker->flows));
    worker->flow_index = calloc(table_capacity, sizeof(*worker->flow_index));
    worker->free_flow_ids = malloc(flow_capacity * sizeof(*worker->free_flow_ids));
    worker->reclaim_candidates = malloc(
        flow_capacity * sizeof(*worker->reclaim_candidates));
    worker->probes = calloc(worker->pending_limit, sizeof(*worker->probes));
    worker->free_probe_ids = malloc(sizeof(*worker->free_probe_ids));
    assert(worker->flows != NULL && worker->flow_index != NULL &&
           worker->free_flow_ids != NULL &&
           worker->reclaim_candidates != NULL && worker->probes != NULL &&
           worker->free_probe_ids != NULL);
    for (size_t i = 0; i < flow_capacity; i++) {
        worker->flows[i].state = UDP_FLOW_EMPTY;
        worker->flows[i].generation = 1U;
        worker->flows[i].upstream_fd = -1;
        worker->flows[i].probe_id = UINT32_MAX;
        worker->free_flow_ids[i] = (uint32_t)(flow_capacity - 1U - i);
    }
    worker->free_flow_count = flow_capacity;
    worker->free_probe_ids[0] = 0U;
    worker->free_probe_count = 1U;
}

static void worker_table_destroy(struct udp_worker *worker) {
    while (worker->flow_count != 0U) {
        for (size_t i = 0; i < worker->flow_capacity; i++) {
            if (worker->flows[i].state != UDP_FLOW_EMPTY) {
                udp_flow_remove(worker, i);
                break;
            }
        }
    }
    free(worker->flows);
    free(worker->flow_index);
    free(worker->free_flow_ids);
    free(worker->reclaim_candidates);
    free(worker->probes);
    free(worker->free_probe_ids);
}

static void test_backward_shift_deletion(void) {
    enum { FLOW_LIMIT = 4, TABLE_CAPACITY = 8, COLLISION_COUNT = 3 };
    struct udp_worker worker;
    worker_table_init(&worker, FLOW_LIMIT, FLOW_LIMIT, TABLE_CAPACITY);

    struct udp_flow_key keys[COLLISION_COUNT];
    size_t found = 0U;
    size_t wanted_home = SIZE_MAX;
    for (uint32_t port = 10000U; port <= UINT16_MAX && found < COLLISION_COUNT;
         port++) {
        struct udp_flow_key candidate = make_key((uint16_t)port);
        size_t home = key_home(&candidate, worker.hash_seed, TABLE_CAPACITY);
        if (wanted_home == SIZE_MAX) wanted_home = home;
        if (home == wanted_home) keys[found++] = candidate;
    }
    assert(found == COLLISION_COUNT);

    size_t ids[COLLISION_COUNT];
    for (size_t i = 0; i < COLLISION_COUNT; i++) {
        assert(udp_flow_insert(&worker, &keys[i], false, &ids[i]) != NULL);
        assert(udp_flow_lookup_id(&worker, &keys[i]) == ids[i]);
    }

    uint32_t old_generation = worker.flows[ids[0]].generation;
    udp_flow_remove(&worker, ids[0]);
    assert(worker.flows[ids[0]].state == UDP_FLOW_EMPTY);
    assert(worker.flows[ids[0]].generation == old_generation + 1U);
    assert(udp_flow_lookup_id(&worker, &keys[0]) == SIZE_MAX);
    assert(udp_flow_lookup_id(&worker, &keys[1]) == ids[1]);
    assert(udp_flow_lookup_id(&worker, &keys[2]) == ids[2]);

    worker_table_destroy(&worker);
}

static void mark_confirmed(struct udp_worker *worker, size_t id,
                           uint64_t last_activity_ms) {
    struct udp_flow *flow = &worker->flows[id];
    flow->state = UDP_FLOW_ACTIVE;
    flow->upstream_confirmed = true;
    flow->last_activity_ms = last_activity_ms;
}

static void test_capacity_expands_and_contracts(void) {
    struct udp_worker worker;
    worker_table_init(&worker, 4U, 8U, 16U);
    uint64_t now = vane_monotonic_ms();

    for (uint16_t port = 12000U; port < 12003U; port++) {
        size_t id = SIZE_MAX;
        struct udp_flow_key key = make_key(port);
        assert(udp_flow_insert(&worker, &key, false, &id) != NULL);
        mark_confirmed(&worker, id, now);
    }
    assert(worker.flow_limit == 4U);

    size_t fourth_id = SIZE_MAX;
    struct udp_flow_key fourth = make_key(12003U);
    assert(udp_flow_insert(&worker, &fourth, false, &fourth_id) != NULL);
    mark_confirmed(&worker, fourth_id, now);
    assert(worker.flow_limit == 8U);
    assert(worker.flow_count == 4U);

    udp_flow_remove(&worker, fourth_id);
    for (size_t i = 0; i < worker.flow_capacity && worker.flow_count > 2U; i++) {
        if (worker.flows[i].state != UDP_FLOW_EMPTY) udp_flow_remove(&worker, i);
    }
    worker.next_expiry_scan_ms = 0U;
    udp_flow_expire(&worker);
    assert(worker.flow_count <= 2U);
    assert(worker.flow_limit == 4U);
    worker_table_destroy(&worker);
}

static void test_pressure_reclaims_oldest_before_expanding(void) {
    struct udp_worker worker;
    worker_table_init(&worker, 4U, 8U, 16U);
    uint64_t now = vane_monotonic_ms();
    struct udp_flow_key oldest_key = make_key(13000U);

    for (uint16_t port = 13000U; port < 13003U; port++) {
        size_t id = SIZE_MAX;
        struct udp_flow_key key = make_key(port);
        assert(udp_flow_insert(&worker, &key, false, &id) != NULL);
        mark_confirmed(&worker, id,
                       port == 13000U ? now - 1000U : now);
    }

    size_t fourth_id = SIZE_MAX;
    struct udp_flow_key fourth = make_key(13003U);
    assert(udp_flow_insert(&worker, &fourth, false, &fourth_id) != NULL);
    assert(udp_flow_lookup_id(&worker, &oldest_key) == SIZE_MAX);
    assert(worker.flow_limit == 4U);
    assert(worker.flow_count == 3U);
    worker_table_destroy(&worker);
}

static void test_hard_idle_removes_confirmed_flow(void) {
    struct udp_worker worker;
    worker_table_init(&worker, 4U, 8U, 16U);
    test_runtime.udp_flow_hard_idle_timeout_ms = 1000U;
    test_runtime.udp_flow_quiescent_after_ms = 100U;

    size_t id = SIZE_MAX;
    struct udp_flow_key key = make_key(14000U);
    assert(udp_flow_insert(&worker, &key, false, &id) != NULL);
    mark_confirmed(&worker, id, vane_monotonic_ms() - 2000U);
    worker.next_expiry_scan_ms = 0U;
    udp_flow_expire(&worker);
    assert(udp_flow_lookup_id(&worker, &key) == SIZE_MAX);
    assert(worker.flow_count == 0U);
    worker_table_destroy(&worker);
}


static void test_reprobe_state_is_reversible(void) {
    struct udp_worker worker;
    worker_table_init(&worker, 4U, 8U, 16U);
    struct vane_target_config target = {0};
    target.location_kind = VANE_LOCATION_ADDRESS;

    size_t id = SIZE_MAX;
    struct udp_flow_key key = make_key(15000U);
    struct udp_flow *flow = udp_flow_insert(&worker, &key, false, &id);
    assert(flow != NULL);
    flow->state = UDP_FLOW_ACTIVE;
    flow->target = &target;
    flow->upstream_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(flow->upstream_fd >= 0);

    struct vane_quic_initial_identity candidate = {
        .version = 1U,
        .source_connection_id = {0x42U},
        .source_connection_id_len = 1U,
    };
    assert(udp_flow_begin_reprobe(&worker, id, &candidate));
    assert(flow->state == UDP_FLOW_REPROBING);
    assert(flow->probe_accounted);
    assert(worker.pending_count == 1U);
    assert(vane_quic_initial_identity_equal(&flow->reprobe_identity,
                                              &candidate));
    udp_flow_cancel_reprobe(&worker, id, "unit test");
    assert(flow->state == UDP_FLOW_ACTIVE);
    assert(!flow->probe_accounted);
    assert(worker.pending_count == 0U);
    assert(flow->reprobe_identity.source_connection_id_len == 0U);

    assert(udp_flow_begin_reprobe(&worker, id, &candidate));
    assert(udp_flow_commit_reprobe(&worker, id, &target));
    assert(flow->state == UDP_FLOW_ACTIVE);
    assert(!flow->probe_accounted);
    assert(worker.pending_count == 0U);

    int established_fd = flow->upstream_fd;
    struct vane_target_config denied = {0};
    denied.location_kind = VANE_LOCATION_DROP;
    assert(udp_flow_begin_reprobe(&worker, id, &candidate));
    assert(!udp_flow_commit_reprobe(&worker, id, &denied));
    assert(flow->state == UDP_FLOW_REPROBING);
    assert(flow->upstream_fd == established_fd);
    assert(flow->target == &target);
    assert(flow->probe_accounted);
    assert(worker.pending_count == 1U);
    udp_flow_cancel_reprobe(&worker, id, "denied candidate");
    assert(flow->state == UDP_FLOW_ACTIVE);
    assert(flow->upstream_fd == established_fd);
    assert(flow->target == &target);
    assert(!flow->probe_accounted);
    assert(worker.pending_count == 0U);

    worker_table_destroy(&worker);
}

static void test_quic_retry_identity_tracking(void) {
    struct udp_flow flow = {0};
    struct vane_quic_initial_identity current = {
        .version = 1U,
        .destination_connection_id = {0x10U, 0x11U},
        .destination_connection_id_len = 2U,
        .source_connection_id = {0x20U, 0x21U},
        .source_connection_id_len = 2U,
    };
    udp_flow_set_quic_identity(&flow, &current);
    assert(udp_flow_quic_identity_matches(&flow, &current));

    struct vane_quic_initial_identity post_retry = current;
    post_retry.destination_connection_id[0] = 0x30U;
    post_retry.destination_connection_id[1] = 0x31U;
    assert(!udp_flow_quic_identity_matches(&flow, &post_retry));

    struct vane_quic_initial_identity retry = {
        .version = 1U,
        .destination_connection_id = {0x20U, 0x21U},
        .destination_connection_id_len = 2U,
        .source_connection_id = {0x30U, 0x31U},
        .source_connection_id_len = 2U,
    };
    udp_flow_note_quic_retry(&flow, &retry);
    assert(flow.has_quic_retry_dcid);
    assert(udp_flow_quic_identity_matches(&flow, &post_retry));

    post_retry.source_connection_id[0] ^= 1U;
    assert(!udp_flow_quic_identity_matches(&flow, &post_retry));

    udp_flow_set_quic_identity(&flow, NULL);
    assert(!flow.has_quic_identity);
    assert(!flow.has_quic_retry_dcid);
}

static void test_event_token_roundtrip(void) {
    uint64_t token = udp_event_token(UDP_EVENT_UPSTREAM, UINT32_C(0x00abc123),
                                     UINT32_C(0x89abcdef));
    assert(udp_token_kind(token) == UDP_EVENT_UPSTREAM);
    assert(udp_token_id(token) == UINT32_C(0x00abc123));
    assert(udp_token_generation(token) == UINT32_C(0x89abcdef));
}

static void test_server_initial_identity_tracking(void) {
    struct udp_flow flow = {0};
    struct vane_quic_initial_identity client = {
        .version = 1U, .destination_connection_id = {1U},
        .destination_connection_id_len = 1U,
        .source_connection_id = {2U}, .source_connection_id_len = 1U,
    };
    struct vane_quic_initial_identity response = {
        .version = 1U, .destination_connection_id = {2U},
        .destination_connection_id_len = 1U,
        .source_connection_id = {3U}, .source_connection_id_len = 1U,
    };
    udp_flow_set_quic_identity(&flow, &client);
    response.version = 2U;
    udp_flow_note_quic_initial(&flow, &response);
    assert(!flow.has_quic_server_dcid);
    response.version = 1U;
    response.destination_connection_id[0] = 9U;
    udp_flow_note_quic_initial(&flow, &response);
    assert(!flow.has_quic_server_dcid);
    response.destination_connection_id[0] = 2U;
    udp_flow_note_quic_retry(&flow, &response);
    struct vane_quic_initial_identity after_retry = client;
    after_retry.destination_connection_id[0] = 3U;
    assert(udp_flow_quic_identity_matches(&flow, &after_retry));
    response.source_connection_id[0] = 4U;
    udp_flow_note_quic_retry(&flow, &response);
    assert(flow.quic_retry_dcid[0] == 3U); /* First Retry wins. */
    udp_flow_note_quic_initial(&flow, &response);
    struct vane_quic_initial_identity after_initial = client;
    after_initial.destination_connection_id[0] = 4U;
    assert(udp_flow_quic_identity_matches(&flow, &after_initial));
    assert(udp_flow_quic_identity_matches(&flow, &after_retry));
    assert(udp_flow_quic_identity_matches(&flow, &client));
    response.source_connection_id[0] = 5U;
    udp_flow_note_quic_initial(&flow, &response);
    assert(flow.quic_server_dcid[0] == 4U); /* First Initial wins. */
    after_initial.source_connection_id[0] = 9U;
    assert(!udp_flow_quic_identity_matches(&flow, &after_initial));
    after_initial.source_connection_id[0] = 2U;
    struct vane_quic_initial_identity replacement = client;
    replacement.source_connection_id[0] = 6U;
    udp_flow_set_quic_identity(&flow, &replacement);
    assert(!flow.has_quic_server_dcid && !flow.has_quic_retry_dcid);
    uint64_t now = vane_monotonic_ms();
    assert(udp_flow_quic_identity_retired(&flow, &client, now));
    assert(udp_flow_quic_identity_retired(&flow, &after_retry, now));
    assert(udp_flow_quic_identity_retired(&flow, &after_initial, now));
    /* Zero-length server SCIDs remain distinguishable from unknown SCIDs. */
    response.destination_connection_id[0] = 6U;
    response.source_connection_id_len = 0U;
    udp_flow_note_quic_initial(&flow, &response);
    replacement.destination_connection_id_len = 0U;
    assert(udp_flow_quic_identity_matches(&flow, &replacement));
    udp_flow_set_quic_identity(&flow, NULL);
    assert(!flow.has_quic_server_dcid);
}

static void test_udp_error_history_reset_is_explicit(void) {
    struct udp_flow flow = {0};
    flow.last_error = ECONNREFUSED;
    flow.last_error_log_ms = 1234U;
    flow.suppressed_errors = 17U;
    udp_flow_clear_error_history(&flow);
    assert(flow.last_error == 0);
    assert(flow.last_error_log_ms == 0U);
    assert(flow.suppressed_errors == 0U);
}
static void test_retired_quic_identities(void) {
    struct udp_flow flow = {0};
    struct vane_quic_initial_identity a = {
        .version = 1U,
        .destination_connection_id = {0x10U},
        .destination_connection_id_len = 1U,
        .source_connection_id = {0x20U},
        .source_connection_id_len = 1U,
    };
    udp_flow_set_quic_identity(&flow, &a);
    struct vane_quic_initial_identity retry = {
        .version = 1U,
        .destination_connection_id = {0x20U},
        .destination_connection_id_len = 1U,
        .source_connection_id = {0x30U},
        .source_connection_id_len = 1U,
    };
    udp_flow_note_quic_retry(&flow, &retry);
    struct vane_quic_initial_identity after_retry = a;
    after_retry.destination_connection_id[0] = 0x30U;
    struct vane_quic_initial_identity b = a;
    b.source_connection_id[0] = 0x40U;
    udp_flow_set_quic_identity(&flow, &b);
    uint64_t now = vane_monotonic_ms();
    assert(udp_flow_quic_identity_retired(&flow, &a, now));
    assert(udp_flow_quic_identity_retired(&flow, &after_retry, now));
    assert(!udp_flow_quic_identity_retired(&flow, &b, now));
    assert(!udp_flow_quic_identity_retired(&flow, &a,
                now + UDP_RETIRED_IDENTITY_MS + 1U));
    for (size_t i = 0U; i < UDP_RETIRED_IDENTITIES + 1U; i++) {
        b.source_connection_id[0]++;
        udp_flow_set_quic_identity(&flow, &b);
    }
    assert(!udp_flow_quic_identity_retired(&flow, &a, now));
}

int main(void) {
    test_server_initial_identity_tracking();
    test_retired_quic_identities();
    test_udp_error_history_reset_is_explicit();
    assert(udp_next_power_of_two(1U) == 1U);
    assert(udp_next_power_of_two(9U) == 16U);
    test_event_token_roundtrip();
    test_backward_shift_deletion();
    test_capacity_expands_and_contracts();
    test_pressure_reclaims_oldest_before_expanding();
    test_hard_idle_removes_confirmed_flow();
    test_reprobe_state_is_reversible();
    test_quic_retry_identity_tracking();
    return 0;
}
