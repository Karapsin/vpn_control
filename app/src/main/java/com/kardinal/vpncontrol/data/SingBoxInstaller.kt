package com.kardinal.vpncontrol.data

import android.content.Context
import java.io.File

object SingBoxInstaller {
    private const val BUNDLED_LIB_NAME = "libsing-box.so"

    fun resolveBinary(context: Context): File {
        val nativeLib = File(context.applicationInfo.nativeLibraryDir, BUNDLED_LIB_NAME)
        if (!nativeLib.exists()) {
            error("Bundled sing-box native library not found at ${nativeLib.absolutePath}")
        }

        // Remove any stale copied binary so the app never falls back to an SELinux-blocked path.
        val staleCopy = RuntimeFiles.singBoxBinary(context)
        if (staleCopy.exists()) {
            staleCopy.delete()
        }

        return nativeLib
    }
}
