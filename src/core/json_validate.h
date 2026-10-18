#ifndef VANE_JSON_VALIDATE_H
#define VANE_JSON_VALIDATE_H
#include "vane/common.h"
bool vane_json_validate_strict(const char *data, size_t len, struct vane_error *err);
#endif
