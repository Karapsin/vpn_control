package com.kardinal.vpncontrol.data

import android.content.Context
import java.io.File

/** Read-only facade: imports must use the application owner's guarded operation. */
class AndroidHomeSshCredentialStore(context: Context) {
    private val versions = AndroidSshCredentialVersions(File(context.filesDir, "credentials"))

    fun privateKeyPathOrNull(version: Long): String? = versions.path(version)
    fun hasPrivateKey(version: Long): Boolean = privateKeyPathOrNull(version) != null
}
