#ifndef VPN_CONTROL_INSTALL_RELAUNCH_PLAN_H
#define VPN_CONTROL_INSTALL_RELAUNCH_PLAN_H

#include <stdbool.h>
#include <stddef.h>

struct install_relaunch_plan {
    const char *executable;
    char *arguments[8];
};

static int install_relaunch_plan_create(struct install_relaunch_plan *plan,
    const char *launcher, const char *bundle, const char *workspace, bool gui) {
    if (!plan || !launcher || !bundle || !workspace) return -1;
    if (gui) {
        plan->executable = "/usr/bin/open";
        plan->arguments[0] = "open";
        plan->arguments[1] = "-n";
        plan->arguments[2] = "-a";
        plan->arguments[3] = (char *)bundle;
        plan->arguments[4] = "--args";
        plan->arguments[5] = "--state-dir";
        plan->arguments[6] = (char *)workspace;
        plan->arguments[7] = NULL;
    } else {
        plan->executable = launcher;
        plan->arguments[0] = (char *)launcher;
        plan->arguments[1] = "--state-dir";
        plan->arguments[2] = (char *)workspace;
        plan->arguments[3] = "serve";
        plan->arguments[4] = NULL;
    }
    return 0;
}

#endif
