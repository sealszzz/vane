#include "vane/version.h"

#include <stdio.h>

#ifndef VANE_VERSION_STRING
#define VANE_VERSION_STRING "unknown"
#endif
#ifndef VANE_GIT_COMMIT
#define VANE_GIT_COMMIT "unknown"
#endif
#ifndef VANE_BUILD_TIME
#define VANE_BUILD_TIME "unknown"
#endif
#ifndef VANE_CPU_TARGET_STRING
#define VANE_CPU_TARGET_STRING "unknown"
#endif

const char *vane_version(void) {
    return VANE_VERSION_STRING;
}

void vane_version_print(void) {
    (void)printf("vane %s\ncommit %s\nbuild %s\ncpu %s\n",
                 vane_version(), VANE_GIT_COMMIT, VANE_BUILD_TIME,
                 VANE_CPU_TARGET_STRING);
}
