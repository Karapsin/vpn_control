package com.kardinal.vpncontrol

object ImportTestHooks {
    var clipboardTextOverride: String?
        get() = null
        set(_) {}

    var qrContentsOverride: String?
        get() = null
        set(_) {}

    fun clear() = Unit
}
