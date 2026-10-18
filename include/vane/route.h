#ifndef VANE_ROUTE_H
#define VANE_ROUTE_H

#include "vane/config.h"
#include "vane/tls_parser.h"

struct vane_route_table;

bool vane_route_table_build(const struct vane_listener_config *listener,
                              struct vane_route_table **out,
                              struct vane_error *err);
void vane_route_table_destroy(struct vane_route_table *table);
const struct vane_target_config *
vane_route_select_tls(const struct vane_route_table *table,
                        const struct vane_client_hello *hello);
const struct vane_target_config *
vane_route_select_fallback(const struct vane_route_table *table);
bool vane_route_has_protocol_rules(const struct vane_route_table *table);

#endif
