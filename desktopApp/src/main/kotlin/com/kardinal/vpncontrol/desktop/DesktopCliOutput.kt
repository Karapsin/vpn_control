package com.kardinal.vpncontrol.desktop

import java.io.OutputStream
import java.nio.charset.StandardCharsets

/** CLI streams are UTF-8 even when a Windows JDK/console uses a legacy default charset. */
internal fun desktopCliPrintLine(message: String) = writeDesktopCliLine(System.out, message)

internal fun writeDesktopCliLine(output: OutputStream, message: String) {
    synchronized(output) {
        output.write(message.toByteArray(StandardCharsets.UTF_8))
        output.write('\n'.code)
        output.flush()
    }
}
