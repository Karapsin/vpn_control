package com.kardinal.vpncontrol.model

object StatusMessages {
    fun encode(
        key: StatusMessageKey,
        vararg args: String,
    ): String = StatusMessageCodec.encode(key, *args)

    fun decode(raw: String): StructuredStatusMessage? = StatusMessageCodec.decode(raw)
}
