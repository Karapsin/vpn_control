package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopPrivateExportWriterTest {
    @Test fun windowsUnenforcedOrInheritedAclIsRejectedByPreWriteGate() {
        val owner = "S-1-5-21-1-2-3-1001"
        val info = WindowsInstallInfo(false, owner = owner, dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, owner)))
        requireWindowsPrivateExport(8, info, owner)
        assertFailsWith<IllegalArgumentException> { requireWindowsPrivateExport(0, info, owner) }
        assertFailsWith<IllegalArgumentException> { requireWindowsPrivateExport(8, info.copy(dacl = null), owner) }
        assertFailsWith<IllegalArgumentException> { requireWindowsPrivateExport(8, info.copy(dacl = listOf(WindowsInstallAce(0, 16, 1, owner))), owner) }
        assertFailsWith<IllegalArgumentException> { requireWindowsPrivateExport(8, info.copy(dacl = listOf(WindowsInstallAce(0, 0, 1, "S-1-1-0"))), owner) }
    }
    @Test fun macInheritedAclIsRejectedBeforeAnySecretBytesAreWritten() {
        assumeTrue(Platform.isMac())
        fixture { dir ->
            val process = ProcessBuilder("/bin/chmod", "+a", "everyone allow read,file_inherit", dir.toString()).start()
            assertEquals(0, process.waitFor())
            val file = dir.resolve("secret")
            assertTrue(DesktopPrivateExportWriter.write(file.toString(), "SECRET".toByteArray()).isFailure)
            if (Files.exists(file)) assertEquals(0L, Files.size(file))
        }
    }
    private fun fixture(test: (Path) -> Unit) {
        val dir = Files.createTempDirectory("private-export-東京")
        try { test(dir) }
        finally { Files.walk(dir).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun bytesArePrivateAndExistingContentIsNeverOverwritten() = fixture { dir ->
        val file = dir.resolve("secret.json")
        val bytes = "private 東京".toByteArray()
        DesktopPrivateExportWriter.write(file.toString(), bytes).getOrThrow()
        assertContentEquals(bytes, Files.readAllBytes(file))
        if (!Platform.isWindows()) assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file))
        assertTrue(DesktopPrivateExportWriter.write(file.toString(), byteArrayOf(1)).isFailure)
        assertContentEquals(bytes, Files.readAllBytes(file))
    }

    @Test fun existingSymlinkNeverWritesItsTarget() {
        assumeFalse(Platform.isWindows()) // Windows creation requires privilege; no elevation in tests.
        fixture { dir ->
            val target = Files.writeString(dir.resolve("target"), "unchanged")
            val link = Files.createSymbolicLink(dir.resolve("export"), target)
            assertTrue(DesktopPrivateExportWriter.write(link.toString(), byteArrayOf(1)).isFailure)
            assertEquals("unchanged", Files.readString(target))
        }
    }

    @Test fun windowsCreationHasOnlyOwnerAllowDespiteInheritableParentAcl() {
        assumeTrue(Platform.isWindows())
        fixture { dir ->
            val file = dir.resolve("secret.png")
            DesktopPrivateExportWriter.write(file.toString(), byteArrayOf(1, 2)).getOrThrow()
            val native = JnaWindowsInstallNative()
            val handle = native.open(file.toString(), WindowsInstallNative.READ, false)
            try {
                val info = native.inspect(handle)
                assertTrue(requireNotNull(info.dacl).isNotEmpty())
                assertTrue(info.dacl.all { it.type == 0 && it.sid == info.owner && it.flags and 0x10 == 0 })
            } finally { native.close(handle) }
        }
    }
}
