package com.kardinal.vpncontrol.data

import androidx.annotation.Keep
import java.io.File
import java.io.IOException

/** Atomic, no-replace publication for private generated files. */
@Keep
internal object AndroidNativePublication {
    private object Library {
        init { System.loadLibrary("vpn_control_strings") }
        fun ready() = Unit
    }

    fun publishNew(source: File, target: File): Boolean {
        try { Library.ready() }
        catch (failure: LinkageError) { throw IOException("Native publication is unavailable", failure) }
        return publishNoReplace(source.path, target.path)
    }

    @JvmStatic private external fun publishNoReplace(source: String, target: String): Boolean
}
