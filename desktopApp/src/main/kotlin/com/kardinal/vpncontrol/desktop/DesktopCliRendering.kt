package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec

/** JSON owns stdout; human failures and incomplete operation progress own stderr. */
internal fun desktopCliRender(response: DesktopCliResponse, json: Boolean,
                              output: (String) -> Unit, progress: (String) -> Unit): Int {
    if (json) output(response.message) else {
        val result = ControlDocumentCodec.decodeResult(response.message)
        val destination = if (result.ok && result.final) output else progress
        destination(desktopAndroidHumanOutput(result))
    }
    return response.exitCode
}
