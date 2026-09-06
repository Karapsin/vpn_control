package com.kardinal.vpncontrol.desktop

import java.io.InputStream
import java.net.SocketTimeoutException

/** One response deadline, including partial frames. Zero means an unlimited wait. */
internal class DesktopControlResponseInputStream(
    private val source: InputStream,
    private val timeoutMillis: Long,
    private val setSocketTimeout: (Int) -> Unit,
    private val nowMillis: () -> Long = responseMonotonicClock(),
) : InputStream() {
    init { require(timeoutMillis >= 0) }
    private val started = nowMillis()

    override fun read(): Int = timedRead { source.read() }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int = timedRead { source.read(bytes, offset, length) }

    private inline fun timedRead(read: () -> Int): Int {
        while (true) {
            if (timeoutMillis == 0L) setSocketTimeout(0)
            else {
                val remaining = timeoutMillis - (nowMillis() - started)
                if (remaining <= 0) throw SocketTimeoutException()
                setSocketTimeout(remaining.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            }
            try { return read() }
            catch (timeout: SocketTimeoutException) {
                if (timeoutMillis == 0L) throw timeout
                // A socket interval can be shorter than a very long client deadline.
                // Retrying this read preserves bytes already consumed by DataInputStream.
            }
        }
    }
}

private fun responseMonotonicClock(): () -> Long {
    val origin = System.nanoTime()
    return { (System.nanoTime() - origin) / 1_000_000 }
}
