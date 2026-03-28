package com.kardinal.vpncontrol.data

import android.content.Context
import java.io.File

object RuntimeFiles {
    fun runtimeConfigFile(context: Context): File = File(context.filesDir, "runtime-sing-box.json")

    fun selectedProfileFile(context: Context): File = File(context.filesDir, "last-profile-link.txt")

    fun diagnosticsLogFile(context: Context): File = File(context.filesDir, "diagnostics.log")

    fun diagnosticsExportDir(context: Context): File = File(context.cacheDir, "exports")

    fun singBoxBinary(context: Context): File = File(context.filesDir, "bin/sing-box")
}
