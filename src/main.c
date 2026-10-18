#include "vane/config.h"
#include "vane/log.h"
#include "vane/runtime.h"
#include "vane/version.h"

#include <stdio.h>
#include <string.h>

static size_t report_config_warnings(const struct vane_config *config) {
    size_t warnings = 0;
    for (size_t i = 0; i < config->listener_count; i++) {
        const struct vane_listener_config *listener = &config->listeners[i];
        if (listener->transport != VANE_TRANSPORT_UDP) continue;
        for (size_t j = 0; j < listener->target_count; j++) {
            const struct vane_target_config *target = &listener->targets[j];
            if (!target->proxy_protocol ||
                target->location_kind != VANE_LOCATION_ADDRESS) continue;
            char listener_buf[96];
            char target_buf[96];
            (void)fprintf(stderr,
                "WARNING: UDP listener %s target %s has proxy_protocol=true; "
                "this prepends a PROXY v2 header to every datagram and is "
                "incompatible with ordinary QUIC servers unless they explicitly "
                "support PROXY v2 datagrams.\n",
                vane_addr_format(&listener->address, listener_buf, sizeof(listener_buf)),
                vane_addr_format(&target->location, target_buf, sizeof(target_buf)));
            warnings++;
        }
    }
    return warnings;
}

static void usage(const char *program) {
    (void)fprintf(stderr,
        "USAGE:\n"
        "  %s <CONFIG.json>\n"
        "  %s --check <CONFIG.json>\n"
        "  %s --version\n",
        program, program, program);
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)) {
        vane_version_print();
        return 0;
    }
    bool check_only = argc == 3 && strcmp(argv[1], "--check") == 0;
    if ((!check_only && argc != 2) || (check_only && argc != 3)) {
        usage(argv[0]);
        return 2;
    }
    const char *config_path = check_only ? argv[2] : argv[1];
    struct vane_config config;
    struct vane_error err = {0};
    if (!vane_config_load(config_path, &config, &err)) {
        (void)fprintf(stderr, "ERROR: %s\n", err.message);
        return 1;
    }
    size_t warnings = report_config_warnings(&config);
    if (check_only) {
        (void)printf("configuration valid: listeners=%zu workers_per_listener=%zu "
                     "worker_threads=%zu warnings=%zu\n",
                     config.listener_count, config.runtime.workers,
                     config.listener_count * config.runtime.workers, warnings);
        vane_config_destroy(&config);
        return 0;
    }
    vane_log_set_level(config.log_level);
    LOG_INFO("loaded config: listeners=%zu workers_per_listener=%zu worker_threads=%zu",
             config.listener_count, config.runtime.workers,
             config.listener_count * config.runtime.workers);
    bool ok = vane_runtime_run(&config, &err);
    if (!ok) LOG_ERROR("runtime failed: %s", err.message);
    vane_config_destroy(&config);
    return ok ? 0 : 1;
}
