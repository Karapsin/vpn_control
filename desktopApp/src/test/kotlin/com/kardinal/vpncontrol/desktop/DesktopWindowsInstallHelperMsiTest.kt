package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopWindowsInstallHelperMsiTest {
    @Test fun fixedMsiAdapterRetainsAdmissionHandlesAndExactNativeOutcomes() = runFixture(false, 19)

    @Test fun systemMsiReadsInertDatabasesWithoutChangingBytesOrStartingInstallation() = runFixture(true, 2)

    private fun runFixture(nativeRead: Boolean, expectedCases: Int) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-helper-msi-")
        val files = listOf(
            "windows-install-native.cs", "windows-install-helper-protocol.cs",
            "windows-install-helper-msi.cs", "windows-install-helper-msi-fixture.cs",
        ).map { name ->
            directory.resolve(name).also { path ->
                javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
            }
        }
        val outputFile = directory.resolve("output.log")
        fun capturedPath(path: String): String {
            val encoded = Base64.getEncoder().encodeToString(path.encodeToByteArray())
            return "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encoded')))"
        }
        try {
            val paths = files.joinToString(",") { capturedPath(it.toString()) }
            val operation = if (nativeRead) "NativeReadOnly(${capturedPath(directory.toString())})" else "Run()"
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                Add-Type -Path @($paths)
                ${'$'}cases=@([InstallerMsiFixtures]::$operation)
                if (${'$'}cases.Count -ne $expectedCases) { throw 'Fixed MSI case count changed' }
                foreach(${'$'}case in ${'$'}cases) { Write-Output ('CASE:'+${'$'}case) }
                Write-Output 'FIXED_INSTALL_MSI_OK'
            """.trimIndent()
            val command = Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command)
                .redirectErrorStream(true).redirectOutput(outputFile.toFile()).start()
            try {
                assertTrue(process.waitFor(45, TimeUnit.SECONDS), "Fixed MSI fixture timed out")
                val output = Files.readString(outputFile)
                assertEquals(0, process.exitValue(), output)
                assertEquals(expectedCases, output.lineSequence().count { it.startsWith("CASE:") }, output)
                assertTrue(output.contains("FIXED_INSTALL_MSI_OK"), output)
            } finally {
                // The native fixture only creates and reads inert databases; it never calls Install().
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Inert MSI fixture child did not exit")
                }
            }
        } finally {
            Files.deleteIfExists(outputFile)
            files.forEach(Files::delete)
            Files.delete(directory)
        }
    }
}
