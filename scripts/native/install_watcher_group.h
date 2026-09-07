#ifndef VPN_CONTROL_INSTALL_WATCHER_GROUP_H
#define VPN_CONTROL_INSTALL_WATCHER_GROUP_H

#include <unistd.h>

/* Preserve session and authority while giving each installer child its own
 * process group before the owner may acknowledge readiness and exit. */
static int install_watcher_group(void) {
    if (getpgrp() == getpid()) return 0;
    return setpgid(0, 0);
}

#endif
