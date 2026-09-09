package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopWindowsInstallHelperEntrypointTest {
    @Test
    fun canonicalRoleDispatchUsesOnlySameAssemblyFactoryAndRejectsInvalidInputsBeforeIt() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-helper-entrypoint-")
        val files = listOf(
            "windows-install-native.cs",
            "windows-install-helper.cs",
            "windows-install-helper-protocol.cs",
            "windows-install-helper-roles.cs",
            "windows-install-helper-msi.cs",
            "windows-install-helper-sessions.cs",
            "windows-install-helper-entrypoint-fixture.cs",
            "windows-install-helper-session-fixture.cs",
        ).map { name ->
            directory.resolve(name).also { path ->
                javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
            }
        }
        val output = directory.resolve("output.log")
        var terminal = false
        try {
            fun encoded(path: java.nio.file.Path) = Base64.getEncoder().encodeToString(path.toString().encodeToByteArray())
            val paths = files.joinToString(",") { path ->
                "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded(path)}')))"
            }
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                Add-Type -Path @($paths)
                Write-Output ([InstallerEntrypointFixtures]::Run())
                Write-Output ([InstallerSessionAdmissionFixtures]::FailedOwnerCloseRetainsExactHandleForRetry())
                Write-Output ([InstallerSessionAdmissionFixtures]::WrongOwnerGenerationIsRejectedBeforeAnyInputLookup())
                Write-Output ([InstallerSessionAdmissionFixtures]::ConstructionFailureKeepsOriginalFailureAndRecordsUncertainCleanup())
                Write-Output ([InstallerSessionAdmissionFixtures]::MissingJobInputReleasesPinnedAncestor())
            """.trimIndent()
            val command = Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start()
            terminal = process.waitFor(45, TimeUnit.SECONDS)
            assertTrue(terminal, "Fixed entrypoint fixture timed out; retained fixture at $directory")
            val text = Files.readString(output)
            assertEquals(0, process.exitValue(), text)
            assertTrue(text.contains("FIXED_INSTALL_ENTRYPOINT_OK"), text)
            assertTrue(text.contains("OWNER_CLOSE_RETRIED"), text)
            assertTrue(text.contains("OWNER_GENERATION_REJECTED"), text)
            assertTrue(text.contains("CONSTRUCTION_FAILURE_RETAINED"), text)
            assertTrue(text.contains("MISSING_INPUT_ANCESTOR_RELEASED"), text)
        } finally {
            if (terminal) {
                Files.deleteIfExists(output)
                files.forEach(Files::delete)
                Files.delete(directory)
            }
        }
    }
}
