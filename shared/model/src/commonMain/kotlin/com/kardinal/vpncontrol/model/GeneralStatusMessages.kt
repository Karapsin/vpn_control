package com.kardinal.vpncontrol.model

object GeneralStatusMessages {
    fun idle(): String =
        StatusMessageCodec.encode(StatusMessageKey.IDLE)

    fun languageSet(languageName: String): String =
        StatusMessageCodec.encode(StatusMessageKey.LANGUAGE_SET, languageName)
}
