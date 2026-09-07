package com.kardinal.vpncontrol.desktop

import java.nio.file.NoSuchFileException

/** Preserve only native ENOENT as absence; permission, IO and trust failures remain unknown. */
internal fun macInstallNativeResult(result: Int, nativeError: Int): Int {
    if (result >= 0) return result
    if (nativeError == 2) throw NoSuchFileException("Protected installer object")
    error("Protected installer storage operation failed")
}
