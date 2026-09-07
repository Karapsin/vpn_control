package com.kardinal.vpncontrol.desktop

import java.nio.file.Path

/** Absolute host-provider paths for injected Darwin APIs; no fixture object is created. */
internal fun desktopMacTestPath(path: String): Path {
    require(path.startsWith('/'))
    return Path.of("").toAbsolutePath().root.resolve(path.removePrefix("/"))
}
