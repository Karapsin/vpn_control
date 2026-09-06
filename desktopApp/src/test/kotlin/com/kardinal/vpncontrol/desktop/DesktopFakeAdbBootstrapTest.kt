package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopFakeAdbBootstrapTest {
    @Test fun unicodeFixturePathSurvivesLegacyWindowsArgumentCodePages() {
        val path = Path.of("fixture 東京 space")
        val argument = "base64:" + Base64.getEncoder().encodeToString(path.toString().toByteArray(Charsets.UTF_8))
        assertTrue(argument.all { it.code < 128 })
        for (encoding in listOf("windows-1252", "windows-1251", "US-ASCII")) {
            val nativeRoundTrip = argument.toByteArray(charset(encoding)).toString(charset(encoding))
            assertEquals(path, FakeAdbMain.decodeRoot(nativeRoundTrip))
        }
        val cli = DesktopJvmCliTestBootstrap.encode(listOf("--state-dir", path.toString(), ""))
        assertTrue(cli.all { argument -> argument.all { it.code < 128 } })
        assertEquals(listOf("--state-dir", path.toString(), ""), cli.map { Base64.getDecoder().decode(it).toString(Charsets.UTF_8) })
    }
}
