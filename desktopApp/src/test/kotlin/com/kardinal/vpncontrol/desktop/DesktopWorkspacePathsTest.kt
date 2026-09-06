package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopWorkspacePathsTest {
    @Test fun ownerPinnedFrontendLaunchRetainsIsolatedWorkspaceAndRejectsMalformedVectors() {
        val parent = Files.createTempDirectory("frontend-workspace-arguments")
        try {
            val epoch = "247516b4-3778-418c-9dd0-d5222c69ae16"
            val arguments = listOf("--frontend-owner", epoch, "--state-dir", "space 東京")
            val parsed = DesktopWorkspacePaths.parse(arguments, parent).getOrThrow()
            assertEquals(listOf("--frontend-owner", epoch), parsed.arguments)
            assertEquals(parent.toRealPath().resolve("space 東京"), parsed.directory)
            for (invalid in listOf(
                listOf("--frontend-owner", "not-an-owner"),
                listOf("--frontend-owner", epoch, "--typo"),
                listOf("--frontend-unknown", epoch),
                listOf("--frontend-owner", epoch, "gui", "show"),
            )) assertTrue(DesktopWorkspacePaths.parse(invalid + listOf("--state-dir", "space 東京"), parent).isFailure)
        } finally { parent.toFile().deleteRecursively() }
    }
    @Test
    fun resolvesUnicodeRelativeDirectoryWithoutCreatingWorkspace() {
        val parent = Files.createTempDirectory("vpn-control-paths")
        try {
            val parsed = DesktopWorkspacePaths.parse(listOf("--state-dir", "東京 office/nested", "status"), parent).getOrThrow()
            assertEquals(parent.toRealPath().resolve("東京 office/nested"), parsed.directory)
            assertEquals(listOf("status"), parsed.arguments)
            assertFalse(Files.exists(parsed.directory))
            assertTrue(DesktopWorkspacePaths.parse(listOf("--state-dir", "one", "--state-dir", "two", "status"), parent).isFailure)
            assertTrue(DesktopWorkspacePaths.parse(listOf("--state-dir", "one", "--android", "status"), parent).isFailure)
            assertTrue(DesktopWorkspacePaths.parse(listOf("--state-dir", "one", "serve", "--typo"), parent).isFailure)
            assertEquals(null, DesktopWorkspacePaths.parse(listOf("--state-dir", "one", "--help"), parent).getOrThrow().directory)
            val child = DesktopWorkspacePaths.parse(listOf(DesktopHeadlessController.ARG, "--state-dir", "one"), parent).getOrThrow()
            assertEquals(listOf(DesktopHeadlessController.ARG), child.arguments)
            assertEquals(parent.toRealPath().resolve("one"), child.directory)
        } finally { parent.toFile().deleteRecursively() }
    }

    @Test
    fun existingDirectoryUsesCanonicalIdentity() {
        val parent = Files.createTempDirectory("vpn-control-canonical")
        try {
            val actual = Files.createDirectory(parent.resolve("actual"))
            assertEquals(actual.toRealPath(), DesktopWorkspacePaths.resolve("actual/../actual", parent))
            assertTrue(DesktopWorkspacePaths.parse(listOf("status", "--state-dir", "actual"), parent).isSuccess)
        } finally { parent.toFile().deleteRecursively() }
    }
}
