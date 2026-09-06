package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertContentEquals

class DesktopCliOutputTest {
    @Test
    fun utf8BytesBypassLegacyPrintStreamEncoding() {
        val bytes = ByteArrayOutputStream()
        val stream = PrintStream(bytes, true, "windows-1251")
        val message = "日本語 Українська العربية 東京"
        writeDesktopCliLine(stream, message)
        assertContentEquals((message + "\n").toByteArray(Charsets.UTF_8), bytes.toByteArray())
    }
}
