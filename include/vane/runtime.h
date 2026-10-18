#ifndef VANE_RUNTIME_H
#define VANE_RUNTIME_H

#include "vane/config.h"

bool vane_runtime_run(const struct vane_config *config,
                        struct vane_error *err);

#endif
