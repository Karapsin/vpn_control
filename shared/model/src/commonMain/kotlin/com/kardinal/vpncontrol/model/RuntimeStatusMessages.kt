package com.kardinal.vpncontrol.model

object RuntimeStatusMessages {
    fun desktopAppInitialized(): String =
        StatusMessageCodec.encode(StatusMessageKey.DESKTOP_APP_INITIALIZED)

    fun runtimeMode(mode: String): String =
        StatusMessageCodec.encode(StatusMessageKey.RUNTIME_MODE, mode)

    fun localProxy(address: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCAL_PROXY, address)

    fun runtimeLog(path: String): String =
        StatusMessageCodec.encode(StatusMessageKey.RUNTIME_LOG, path)

    fun preflightPassed(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.PREFLIGHT_PASSED, appMode.name)

    fun preflightFailed(appMode: AppMode, failedChecks: Int): String =
        StatusMessageCodec.encode(StatusMessageKey.PREFLIGHT_FAILED, appMode.name, failedChecks.toString())

    fun desktopVpnCapabilityReady(): String =
        StatusMessageCodec.encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY)

    fun desktopVpnCapabilityError(detail: String): String =
        StatusMessageCodec.encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR, detail)
}
