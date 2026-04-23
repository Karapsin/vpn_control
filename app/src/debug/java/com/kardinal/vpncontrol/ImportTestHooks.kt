package com.kardinal.vpncontrol

object ImportTestHooks {
    @Volatile
    var clipboardTextOverride: String? = null

    @Volatile
    var qrContentsOverride: String? = null

    fun clear() {
        clipboardTextOverride = null
        qrContentsOverride = null
    }
}
