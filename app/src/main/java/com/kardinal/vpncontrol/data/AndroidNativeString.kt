package com.kardinal.vpncontrol.data

import androidx.annotation.Keep
import com.kardinal.vpncontrol.control.ControlTransferSpool
import java.io.IOException

/** Standard JNI construction avoids a second document-sized Java input array. */
@Keep
internal object AndroidNativeString {
    private object Library {
        init { System.loadLibrary("vpn_control_strings") }
        fun ready() = Unit
    }

    fun decode(spool: ControlTransferSpool, count: Int, ascii: Boolean, byteCount: Long,
        byteOffset: Long = 0): String {
        require(count >= 0 && byteOffset >= 0)
        require(byteCount == count.toLong() * if (ascii) 1 else 2)
        require(byteOffset <= Long.MAX_VALUE - byteCount)
        try { Library.ready() }
        catch (failure: LinkageError) { throw IOException("Native string construction is unavailable", failure) }
        return construct(AndroidNativeStringReader(spool, byteOffset, byteCount), count, ascii)
    }

    @JvmStatic private external fun construct(reader: AndroidNativeStringReader, count: Int, ascii: Boolean): String
}

/** This callback exposes only bounded reads of an already owned, private spool. */
@Keep
internal class AndroidNativeStringReader(
    private val spool: ControlTransferSpool,
    private val start: Long,
    private val byteCount: Long,
) {
    fun read(offset: Long, count: Int): ByteArray {
        if (count !in 1..65536 || offset < 0 || offset > byteCount || count.toLong() > byteCount - offset)
            throw IOException("Private string input range is invalid")
        return spool.read(start + offset, count)
    }
}
