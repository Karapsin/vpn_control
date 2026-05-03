package com.kardinal.vpncontrol.model

object DiagnosticsStatusMessages {
    fun diagnosticsExportCanceled(): String =
        StatusMessageCodec.encode(StatusMessageKey.DIAGNOSTICS_EXPORT_CANCELED)

    fun diagnosticsExportedTo(path: String): String =
        StatusMessageCodec.encode(StatusMessageKey.DIAGNOSTICS_EXPORTED_TO, path)

    fun diagnosticsExportFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.DIAGNOSTICS_EXPORT_FAILED)

    fun diagnosticsDestinationOpenFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.DIAGNOSTICS_DESTINATION_OPEN_FAILED)

    fun diagnosticsExportOpened(): String =
        StatusMessageCodec.encode(StatusMessageKey.DIAGNOSTICS_EXPORT_OPENED)

    fun appsLoadFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.APPS_LOAD_FAILED)
}
