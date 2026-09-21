#ifndef VPN_CONTROL_INSTALL_LAUNCHER_ENVIRONMENT_H
#define VPN_CONTROL_INSTALL_LAUNCHER_ENVIRONMENT_H

#include <stdlib.h>

/* Keep this primitive isolated so the original-user return path can be exercised
 * on every POSIX host without involving installer authority or a GUI session. */
static int install_launcher_environment(void) {
    return unsetenv("_JPACKAGE_LAUNCHER");
}

#endif
