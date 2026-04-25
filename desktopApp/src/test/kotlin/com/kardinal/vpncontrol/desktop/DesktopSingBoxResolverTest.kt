package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopSingBoxResolverTest {
    @Test
    fun resolvesBundledExecutableFromResources() {
        val tempDir = Files.createTempDirectory("vpn-control-sing-box-resolver")
        try {
            val resolved = DesktopSingBoxResolver(
                toolsDir = tempDir,
                classLoader = javaClass.classLoader,
            ).resolve()

            assertNotNull(resolved)
            assertTrue(Files.exists(resolved.path))
            assertTrue(resolved.source.startsWith("bundled "))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
