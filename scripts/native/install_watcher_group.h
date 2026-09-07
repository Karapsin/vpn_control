#ifndef VPN_CONTROL_INSTALL_WATCHER_GROUP_H
#define VPN_CONTROL_INSTALL_WATCHER_GROUP_H

#include <unistd.h>

/* Preserve the original user's session while giving the return watcher its
 * own process group before the owner may acknowledge installer readiness. */
static int install_watcher_group(void) {
    if (getpgrp() == getpid()) return 0;
    return setpgid(0, 0);
}

#endif
