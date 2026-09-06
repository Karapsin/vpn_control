package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.net.SocketTimeoutException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DesktopControlResponseInputStreamTest {
    @Test
    fun totalDeadlineDoesNotRestartAfterPartialReads() {
        var now = 0L
        val intervals = mutableListOf<Int>()
        val input = DesktopControlResponseInputStream(ByteArrayInputStream(byteArrayOf(1, 2)), 100,
            intervals::add, { now })
        assertEquals(1, input.read())
        now = 80
        assertEquals(2, input.read())
        assertEquals(listOf(100, 20), intervals)
        now = 100
        assertFailsWith<SocketTimeoutException> { input.read() }
    }

    @Test
    fun longSocketIntervalsPreservePartiallyReadFrameAndZeroIsUnlimited() {
        val encoded = ByteArrayOutputStream().also { DesktopControlFrames.write(DataOutputStream(it), "東京") }.toByteArray()
        var now = 0L
        var index = 0
        var expired = false
        val source = object : InputStream() {
            override fun read(): Int {
                if (index == 2 && !expired) {
                    expired = true
                    now += Int.MAX_VALUE
                    throw SocketTimeoutException()
                }
                return if (index == encoded.size) -1 else encoded[index++].toInt() and 255
            }
        }
        val intervals = mutableListOf<Int>()
        val input = DesktopControlResponseInputStream(source, Int.MAX_VALUE.toLong() + 100, intervals::add, { now })
        assertEquals("東京", DesktopControlFrames.read(DataInputStream(input)))
        assertTrue(Int.MAX_VALUE in intervals)
        assertTrue(100 in intervals)
        val unlimited = DesktopControlResponseInputStream(ByteArrayInputStream(byteArrayOf(3)), 0,
            { assertEquals(0, it) }, { Long.MAX_VALUE })
        assertEquals(3, unlimited.read())
    }
}
