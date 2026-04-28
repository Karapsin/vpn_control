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

    @Test
    fun resolvesDarwinArm64BundledExecutableFromResources() {
        val tempDir = Files.createTempDirectory("vpn-control-sing-box-resolver-darwin-arm64")
        try {
            val resolved = DesktopSingBoxResolver(
                toolsDir = tempDir,
                classLoader = javaClass.classLoader,
                osNameOverride = "Mac OS X",
                osArchOverride = "aarch64",
            ).resolve()

            assertNotNull(resolved)
            assertTrue(Files.exists(resolved.path))
            assertTrue(Files.isExecutable(resolved.path))
            assertTrue(resolved.source == "bundled bin/darwin-arm64/sing-box")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun resolvesDarwinAmd64BundledExecutableFromResources() {
        val tempDir = Files.createTempDirectory("vpn-control-sing-box-resolver-darwin-amd64")
        try {
            val resolved = DesktopSingBoxResolver(
                toolsDir = tempDir,
                classLoader = javaClass.classLoader,
                osNameOverride = "Darwin",
                osArchOverride = "x86_64",
            ).resolve()

            assertNotNull(resolved)
            assertTrue(Files.exists(resolved.path))
            assertTrue(Files.isExecutable(resolved.path))
            assertTrue(resolved.source == "bundled bin/darwin-amd64/sing-box")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
