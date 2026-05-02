package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.UnsupportedRemoteSourceResolution
import com.kardinal.vpncontrol.data.parseDirectRemoteSource

internal object DesktopSubscriptionSourceValidation {
    fun validate(raw: String): Result<Unit> {
        return runCatching {
            when (val parsed = parseDirectRemoteSource(raw)) {
                is DirectRemoteSourceResolution -> Unit
                is UnsupportedRemoteSourceResolution -> error(parsed.errorMessage)
                null -> error("Paste a valid https:// subscription URL")
            }
        }
    }
}
