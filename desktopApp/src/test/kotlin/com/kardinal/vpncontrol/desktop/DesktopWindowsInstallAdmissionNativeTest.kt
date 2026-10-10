package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopWindowsInstallAdmissionNativeTest {
    @Test fun nativeReservationLockBlocksFullGateReadButLeavesExactApplicationPrefixReadable() {
        assumeTrue("Requires Windows Win32 byte-range lock semantics", Platform.isWindows())
        val path = Files.createTempFile("admission-reservation-gate-", ".bin")
        val payload = ByteArray(17).apply { this[8] = 1; this[16] = 127 }
        Files.write(path, payload)
        val native = JnaWindowsInstallAdmission()
        try {
            val reader = native.openGate(path.toString())
            try {
                assertTrue(native.lockShared(reader))
                FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE).use { writer ->
                    writer.tryLock(16, 1, false).use { reservation ->
                        assertNotNull(reservation, "Inert coordinator must own only [16,17)")
                        assertEquals(17L, native.inspect(reader).size)
                        assertEquals(33, assertFailsWith<WindowsInstallNativeFailure> {
                            native.readGate(reader)
                        }.code)
                        assertContentEquals(payload.copyOfRange(0, 16), native.readGatePrefix(reader))
                        assertNull(writer.tryLock(0, 1, false), "Control retains shared admission byte0")
                        native.unlockShared(reader)
                        writer.tryLock(0, 1, false).use { replacement ->
                            assertNotNull(replacement)
                            assertFalse(native.lockShared(reader), "Exclusive replacement still bars control")
                        }
                    }
                }
                assertContentEquals(payload, native.readGate(reader))
            } finally { native.close(reader) }
        } finally { Files.delete(path) }
    }

    @Test fun defaultProgramDataAllowsMissingGateForBothPackagedLauncherNamesWithoutWrites() {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("admission-legacy-東京")
        val launchers = listOf("vpn-control.exe", "vpn-control-cli.exe").map(root::resolve)
        try {
            for (launcher in launchers) {
                // Admission now retains the actual executable even before a gate exists.
                // A missing fixture file must fail closed, not bypass that physical pin.
                assertEquals(2, assertFailsWith<WindowsInstallNativeFailure> {
                    DesktopWindowsInstallAdmission.enter(launcher).close()
                }.code)
                val bytes = "inert native admission fixture".toByteArray()
                Files.write(launcher, bytes, StandardOpenOption.CREATE_NEW)
                val modified = Files.getLastModifiedTime(launcher)
                DesktopWindowsInstallAdmission.enter(launcher).use {
                    assertContentEquals(bytes, Files.readAllBytes(launcher))
                }
                assertEquals(modified, Files.getLastModifiedTime(launcher))
                assertContentEquals(bytes, Files.readAllBytes(launcher))
            }
            assertEquals(launchers.toSet(), Files.list(root).use { it.toList().toSet() })
        } finally {
            launchers.forEach(Files::deleteIfExists)
            Files.delete(root)
        }
    }

    @Test fun exactNativeUnicodeIdentityIsStableAcrossCaseAliasesAndRepeatedCalls() {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("admission-東京")
        val native = JnaWindowsInstallAdmission()
        try {
            val first = native.openDirectory(root.toString())
            val alias = native.openDirectory(root.toString().uppercase(java.util.Locale.ROOT))
            try {
                val canonical = native.canonicalPath(first)
                assertTrue(canonical.startsWith("\\\\?\\"))
                val normalized = native.invariantUppercase(canonical)
                assertEquals(canonical.length, normalized.length)
                assertFalse('\u0000' in normalized)
                val identity = DesktopWindowsInstallAdmission.installationId(normalized)
                repeat(100) {
                    assertEquals(identity, DesktopWindowsInstallAdmission.installationId(
                        native.invariantUppercase(native.canonicalPath(alias))))
                }
                assertTrue(native.persistentAcl(first))
            } finally { native.close(alias); native.close(first) }
        } finally { Files.delete(root) }
    }

    @Test fun nativeSharedGateLockCoexistsWithReadersButExcludesInstallerWriter() {
        assumeTrue(Platform.isWindows())
        val path = Files.createTempFile("admission-gate-", ".bin")
        Files.write(path, ByteArray(17))
        val native = JnaWindowsInstallAdmission()
        try {
            val first = native.openGate(path.toString())
            val second = native.openGate(path.toString())
            try {
                assertTrue(native.lockShared(first))
                assertTrue(native.lockShared(second))
                assertContentEquals(ByteArray(17), native.readGate(first))
                FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE).use { writer ->
                    assertNull(writer.tryLock(0, 1, false))
                    native.unlockShared(first)
                    native.unlockShared(second)
                    writer.tryLock(0, 1, false).use { exclusive ->
                        assertNotNull(exclusive)
                        assertFalse(native.lockShared(first))
                    }
                }
            } finally { native.close(second); native.close(first) }
        } finally { Files.delete(path) }
    }
}
