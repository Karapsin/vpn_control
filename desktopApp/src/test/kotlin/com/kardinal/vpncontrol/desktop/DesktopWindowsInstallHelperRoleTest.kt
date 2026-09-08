package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopWindowsInstallHelperRoleTest {
    @Test fun fixedRoleCorePreservesNativeOutcomeAndAdmissionOrderingWithoutInstalling() = runFixture("Run", 18)

    @Test fun validCommitSurvivesOwnerExitBeforeTheNextCoordinatorPoll() = runFixture("CommittedOwnerExit", 0)

    @Test fun undefinedReceiptPhaseIsRejected() = runFixture("UndefinedReceiptPhase", 0)

    @Test fun cancellationPublicationFailureBeforeReplacementRetainsUncertainty() =
        runFixture("CancelFailureBeforeReplacement", 0)

    @Test fun cancellationPublicationFailureAfterReplacementPreservesTerminalIdentity() =
        runFixture("CancelFailureAfterReplacement", 0)

    private fun runFixture(operation: String, expectedCases: Int) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-helper-role-")
        val files = listOf(
            "windows-install-native.cs", "windows-install-helper-protocol.cs",
            "windows-install-helper-roles.cs", "windows-install-helper-role-fixture.cs",
        ).map { name ->
            directory.resolve(name).also { path ->
                javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
            }
        }
        val outputFile = directory.resolve("output.log")
        try {
            val paths = files.joinToString(",") { path ->
                val encoded = Base64.getEncoder().encodeToString(path.toString().encodeToByteArray())
                "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encoded')))"
            }
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                Add-Type -Path @($paths)
                ${'$'}cases=@([InstallerRoleFixtures]::$operation())
                if (${'$'}cases.Count -ne $expectedCases) { throw 'Fixed role case count changed' }
                foreach(${'$'}case in ${'$'}cases) { Write-Output ('CASE:'+${'$'}case) }
                Write-Output 'FIXED_INSTALL_ROLES_OK:$operation'
            """.trimIndent()
            val command = Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command)
                .redirectErrorStream(true).redirectOutput(outputFile.toFile()).start()
            try {
                assertTrue(process.waitFor(45, TimeUnit.SECONDS), "Fixed role fixture timed out")
                val output = Files.readString(outputFile)
                assertEquals(0, process.exitValue(), output)
                assertEquals(expectedCases, output.lineSequence().count { it.startsWith("CASE:") }, output)
                assertTrue(output.contains("FIXED_INSTALL_ROLES_OK:$operation"), output)
            } finally {
                // This exact child only compiles/runs inert role adapters; it never starts an installer or runtime.
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Inert fixture child did not exit")
                }
            }
        } finally {
            Files.deleteIfExists(outputFile)
            files.forEach(Files::delete)
            Files.delete(directory)
        }
    }
}
