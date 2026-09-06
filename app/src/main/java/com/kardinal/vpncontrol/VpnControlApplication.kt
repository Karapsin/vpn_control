package com.kardinal.vpncontrol

import android.app.Application
import android.util.Log
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.io.File
import java.util.Locale

class VpnControlApplication : Application() {
    internal val controlOwner: AndroidApplicationOwner by lazy { AndroidApplicationOwner(this) }

    override fun onCreate() {
        super.onCreate()

        runCatching {
            val baseDir = filesDir.apply { mkdirs() }
            val workingDir = (getExternalFilesDir(null) ?: baseDir).apply { mkdirs() }
            val tempDir = cacheDir.apply { mkdirs() }

            Libbox.setLocale(Locale.getDefault().toLanguageTag().replace("-", "_"))
            Libbox.setup(
                SetupOptions().apply {
                    basePath = baseDir.path
                    workingPath = workingDir.path
                    tempPath = tempDir.path
                    fixAndroidStack = true
                },
            )
            Libbox.redirectStderr(File(workingDir, "stderr.log").path)
        }.onFailure { error ->
            Log.e(TAG, "Failed to initialize libbox", error)
        }
    }

    companion object {
        private const val TAG = "VpnControlApp"
    }
}
