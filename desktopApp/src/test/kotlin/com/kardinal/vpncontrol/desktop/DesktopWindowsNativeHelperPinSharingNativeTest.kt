package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Windows only: the native helpers' compiled pins on real temporary folders. Other programs' renames and hard
 * links into a folder pinned by VpnInstallNative.OpenDirectory or windows-vpn-user-files.cs PinParents succeed,
 * the pinned folder cannot be moved, the witness cannot be deleted, and an image pinned by OpenFile refuses
 * writers. DesktopWindowsNativeHelperPinSharingTest judges the same pins from their source on every platform.
 */
class DesktopWindowsNativeHelperPinSharingNativeTest {
    @Test fun nativeFolderPinsLetOtherProgramsRenameAndLinkIntoTheirFoldersWhileImagePinsRefuseWriters() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val root = Files.createTempDirectory("vpn-native-pin-sharing-")
        val names = listOf("windows-install-native.cs", "windows-vpn-user-files.cs", "windows-vpn-cache-resources.cs",
            "windows-native-pin-sharing-probe.ps1")
        names.forEach { name ->
            requireNotNull(javaClass.getResourceAsStream("/$name")).use { input -> Files.newOutputStream(root.resolve(name)).use(input::copyTo) }
        }
        val script = """
            ${'$'}ErrorActionPreference='Stop'; ${'$'}ProgressPreference='SilentlyContinue'
            ${'$'}root=${'$'}env:VPN_CONTROL_PIN_SHARING_FIXTURE
            Add-Type -Path (Join-Path ${'$'}root 'windows-install-native.cs')
            Add-Type -Path @((Join-Path ${'$'}root 'windows-vpn-user-files.cs'),(Join-Path ${'$'}root 'windows-vpn-cache-resources.cs')) -ReferencedAssemblies @('System.dll','System.Core.dll')
            & ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path ${'$'}root 'windows-native-pin-sharing-probe.ps1'))))
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).also { it.environment()["VPN_CONTROL_PIN_SHARING_FIXTURE"] = root.toString() }.start()
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly() // Only this compiler and probe, on its own temporary folders, are owned.
            fail("Native pin sharing probe timed out; evidence retained at $root")
        }
        val output = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.lineSequence().any { it.trim().startsWith("NATIVE_PIN_SHARING_OK ") }, output)
        names.forEach { Files.delete(root.resolve(it)) }
        Files.delete(root)
    }
}
