package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopWindowsInstallAdmissionTest {
    @Test fun firstGateCreationCannotLoseTheAlreadyRunningExecutablePin() {
        for (missingRoot in listOf(false, true)) {
            val fake = Fake().apply {
                absentGate = !missingRoot
                if (missingRoot) directoryFailure = WindowsInstallNativeFailure(2)
            }
            val lease = DesktopWindowsInstallAdmission.enter(LAUNCHER, fake)
            val executable = fake.handles.singleOrNull { it.path == LAUNCHER.toString() }
            assertNotNull(executable, "The actual running executable must fence the first installer gate")
            assertFalse(executable.closed)
            assertTrue(fake.handles.none { it.closed })
            // A subsequently created first gate cannot retroactively register this process.
            // Its executable handle must therefore remain until the process lease closes.
            fake.absentGate = false
            fake.directoryFailure = null
            assertFalse(executable.closed)
            lease.close()
            assertTrue(executable.closed)
        }
    }

    @Test fun ordinaryUngatedStartupStillRejectsReplacedOrNonphysicalExecutable() {
        val changes: List<(WindowsInstallInfo) -> WindowsInstallInfo> = listOf(
            { it.copy(attributes = 0x400) }, { it.copy(reparseTag = 1) },
            { it.copy(disk = false) }, { it.copy(directory = true) }, { it.copy(links = 2) },
        )
        for (change in changes) {
            val fake = Fake().apply {
                absentGate = true
                inspectTransform = { path, info -> if (path.endsWith("vpn-control.exe")) change(info) else info }
            }
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake) }
            assertTrue(fake.handles.all { it.closed })
        }
        val unrelated = Fake().apply {
            absentGate = true
            canonicalTransform = { path -> if (path.endsWith("vpn-control.exe")) "C:\\Elsewhere\\vpn-control.exe" else path }
        }
        assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, unrelated) }
        assertTrue(unrelated.handles.all { it.closed })
    }

    @Test fun failedPhysicalPinCloseCanBeRetriedWithoutLosingOwnership() {
        val fake = Fake().apply { absentGate = true }
        val lease = DesktopWindowsInstallAdmission.enter(LAUNCHER, fake)
        val retained = fake.handles.lastOrNull { !it.closed }
        assertNotNull(retained, "Missing gate must retain the physical copy")
        fake.closeFailure = retained
        assertFailsWith<WindowsInstallNativeFailure> { lease.close() }
        assertFalse(retained.closed)
        lease.close()
        assertTrue(fake.handles.all { it.closed })
    }

    @Test fun runnerVolumeOwnerDoesNotRequireInstallerAuthorityForOrdinaryStartup() {
        val fake = Fake().apply {
            directoryFailure = WindowsInstallNativeFailure(2)
            inspectTransform = { path, info -> if (path == "D:\\") runnerVolumeInfo() else info }
        }
        val lease = DesktopWindowsInstallAdmission.enter(Path.of("D:\\a\\vpn_control\\vpn-control-cli.exe"), fake)
        assertFalse("lock" in fake.events)
        assertTrue(fake.handles.isNotEmpty())
        assertTrue(fake.handles.none { it.closed }, "Retain the running copy's physical ancestry until exit")
        lease.close()
        assertTrue(fake.handles.all { it.closed })
    }

    @Test fun existingProtectedGateStillRequiresInstallerAuthorityForTheApplication() {
        val fake = Fake().apply {
            inspectTransform = { path, info -> if (path == "D:\\") runnerVolumeInfo() else info }
        }
        val failure = assertFails {
            DesktopWindowsInstallAdmission.enter(Path.of("D:\\a\\vpn_control\\vpn-control-cli.exe"), fake)
        }
        assertEquals("Untrusted installer owner", failure.message)
        assertFalse("read" in fake.events)
        assertTrue(fake.handles.all { it.closed })
    }

    @Test fun onlyValidatedPendingGateSelectsControlOnlyStartup() {
        for (pending in listOf(false, true)) {
            val fake = Fake().apply { if (pending) bytes[8] = 1 }
            var observed = false
            DesktopWindowsInstallAdmission.enter(LAUNCHER, fake, allowPendingControl = true,
                onPendingControl = { observed = true }).use { assertEquals(pending, observed) }
        }
        var observed = false
        DesktopWindowsInstallAdmission.enter(LAUNCHER, Fake().apply { absentGate = true },
            allowPendingControl = true, onPendingControl = { observed = true }).close()
        assertFalse(observed, "Legacy/clear startup must retain ordinary CLI bootstrap")
    }

    @Test fun pendingInstallerAndLockContentionRejectStartupWithoutWrites() {
        for (fake in listOf(Fake().apply { bytes[8] = 1 }, Fake().apply { lockAvailable = false },
            Fake().apply { readFailure = WindowsInstallNativeFailure(33) })) {
            val failure = assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake).close() }
            assertEquals("BUSY", failure.message)
            assertTrue(fake.handles.all { it.closed })
        }
    }
    @Test fun readAfterSharedLockAndRetainEveryPinUntilClose() {
        val fake = Fake()
        val lease = DesktopWindowsInstallAdmission.enter(LAUNCHER, fake)
        assertTrue(fake.events.indexOf("lock") in 0 until fake.events.indexOf("read"))
        assertTrue(fake.handles.isNotEmpty())
        assertTrue(fake.handles.none { it.closed })
        lease.close(); lease.close()
        assertEquals(1, fake.events.count { it == "unlock" })
        assertTrue(fake.handles.all { it.closed })
    }

    @Test fun attributeRightsRequireLinkedRetainedChildAndNeverRelaxProtectedObjects() {
        val info = WindowsInstallInfo(true, owner = "S-1-5-18",
            dacl = listOf(WindowsInstallAce(0, 0, 0x116, "S-1-5-32-545")))
        assertFails { WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.ANCESTOR) }
        assertFails { WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.DIRECTORY, ancestorPinnedNonEmpty = true) }
        assertFails { WindowsInstallTrust.verify(info.copy(directory = false), WindowsInstallTrust.Kind.STATUS, ancestorPinnedNonEmpty = true) }
        for (missing in listOf(true, false)) {
            val fake = Fake().apply {
                childNames = if (missing) emptyList() else listOf("witness")
                canonicalTransform = { path -> if (path.endsWith("witness")) "C:\\elsewhere\\witness" else path }
                inspectTransform = { path, value -> if (path == "C:\\ProgramData") info else value }
            }
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake) }
            assertTrue(fake.handles.all { it.closed })
            assertFalse("lock" in fake.events)
        }
    }
    @Test fun missingLegacyGateIsNoopButMalformedProtectedGateFailsClosed() {
        val missing = Fake().apply { absentGate = true }
        DesktopWindowsInstallAdmission.enter(LAUNCHER, missing).close()
        assertFalse("lock" in missing.events)
        assertTrue(missing.handles.all { it.closed })
        for (bytes in listOf(ByteArray(16), ByteArray(18), ByteArray(17).apply { this[16] = 1 }, ByteArray(17).apply { this[8] = 2 })) {
            val fake = Fake().apply { this.bytes = bytes }
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake).close() }
            assertTrue(fake.handles.all { it.closed })
        }
    }

    @Test fun hostileAncestorsAndGateMetadataFailClosedAndReleaseAllPins() {
        val changes: List<(WindowsInstallInfo) -> WindowsInstallInfo> = listOf(
            { it.copy(owner = "S-1-1-0") },
            { it.copy(dacl = null) },
            { it.copy(dacl = it.dacl.orEmpty() + WindowsInstallAce(0, 0, 0x40, "S-1-1-0")) },
            { it.copy(attributes = 0x400) },
            { it.copy(reparseTag = 1) },
            { it.copy(disk = false) },
        )
        for (target in listOf("C:\\Apps", "C:\\ProgramData", "gate-")) for (change in changes) {
            val fake = Fake().apply { inspectTransform = { path, info -> if (path.contains(target)) change(info) else info } }
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake) }
            assertTrue(fake.handles.all { it.closed })
            assertFalse("read" in fake.events)
        }
        for (fake in listOf(Fake().apply { aclVolume = false }, Fake().apply {
            inspectTransform = { path, info -> if (path.contains("gate-")) info.copy(links = 2) else info }
        })) {
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, fake) }
            assertTrue(fake.handles.all { it.closed })
        }
    }

    @Test fun missingProductRootIsLegacyButAccessDeniedIsNot() {
        val missing = Fake().apply { directoryFailure = WindowsInstallNativeFailure(2) }
        DesktopWindowsInstallAdmission.enter(LAUNCHER, missing).close()
        assertTrue(missing.handles.all { it.closed })
        val denied = Fake().apply { directoryFailure = WindowsInstallNativeFailure(5) }
        assertFailsWith<WindowsInstallNativeFailure> { DesktopWindowsInstallAdmission.enter(LAUNCHER, denied) }
        assertTrue(denied.handles.all { it.closed })
    }

    @Test fun actualDefaultProgramDataAclAllowsLegacyStartupWithoutProductRoot() {
        val fake = Fake().apply {
            directoryFailure = WindowsInstallNativeFailure(2)
            inspectTransform = { path, info ->
                if (path == "C:\\ProgramData") info.copy(dacl = info.dacl.orEmpty() +
                    WindowsInstallAce(0, 0, 0x116, "S-1-5-32-545")) else info
            }
        }
        DesktopWindowsInstallAdmission.enter(LAUNCHER, fake).close()
        assertFalse("lock" in fake.events)
        assertTrue(fake.handles.all { it.closed })
    }

    @Test fun identityUsesExactExtendedPathUtf8DigestWithoutUuidRewriting() {
        assertEquals("e8585fd4-be75-f0e5-80a5-95f2fde18b3c",
            DesktopWindowsInstallAdmission.installationId("\\\\?\\C:\\APPS\\東京"))
        for (invalid in listOf("C:\\APPS", "\\\\?\\C:\\A\u0000", "\\\\?\\C:\\A\uD800")) {
            assertFails { DesktopWindowsInstallAdmission.installationId(invalid) }
        }
    }

    @Test fun reservationByteLockAllowsOnlyValidatedControlPrefixAndRetainsAllPins() {
        // Model the coordinator's exclusive [16,17) reservation mechanically. The
        // production full read overlaps it, while the application prefix does not.
        val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1; this[16] = 127 })
        var pending = 0
        val lease = DesktopWindowsInstallAdmission.enter(LAUNCHER, reader,
            allowPendingControl = true, onPendingControl = { pending++ })
        assertEquals(1, pending)
        assertEquals(listOf(0 to 18, 0 to 16), reader.reads)
        assertTrue(reader.fake.handles.none { it.closed })
        assertEquals(0, reader.fake.events.count { it == "unlock" })
        lease.close()
        assertEquals(1, reader.fake.events.count { it == "unlock" })
        assertTrue(reader.fake.handles.all { it.closed })
    }

    @Test fun reservationByteLockStillRejectsOrdinaryStartupAndExclusiveReplacement() {
        for (replacement in listOf(false, true)) {
            val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1 })
            if (replacement) reader.exclusiveRanges += 0 until 1
            val failure = assertFails {
                DesktopWindowsInstallAdmission.enter(LAUNCHER, reader,
                    allowPendingControl = replacement).close()
            }
            assertEquals("BUSY", failure.message)
            assertEquals(if (replacement) emptyList() else listOf(0 to 18), reader.reads)
            assertTrue(reader.fake.handles.all { it.closed })
        }
    }

    @Test fun reservationFallbackRejectsClearMalformedShortAndInaccessiblePrefixes() {
        val malformed = (0 until 16).filter { it != 8 }.map { index ->
            ByteArray(16).apply { this[8] = 1; this[index] = 1 }
        } + listOf(ByteArray(16), ByteArray(16).apply { this[8] = 2 },
            ByteArray(15).apply { this[8] = 1 }, ByteArray(17).apply { this[8] = 1 })
        for (prefix in malformed) {
            val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1 }).apply {
                returnedPrefix = prefix
            }
            var observed = false
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, reader,
                allowPendingControl = true, onPendingControl = { observed = true }).close() }
            assertFalse(observed)
            assertEquals(listOf(0 to 18, 0 to 16), reader.reads)
            assertTrue(reader.fake.handles.all { it.closed })
        }
        for (code in listOf(5, 33)) {
            val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1 }).apply {
                prefixFailure = WindowsInstallNativeFailure(code)
            }
            assertEquals(code, assertFailsWith<WindowsInstallNativeFailure> {
                DesktopWindowsInstallAdmission.enter(LAUNCHER, reader, allowPendingControl = true).close()
            }.code)
            assertTrue(reader.fake.handles.all { it.closed })
        }
    }

    @Test fun reservationFallbackStillRequiresExactPhysicalGateSizeAndTrustedPaths() {
        for (size in listOf(16, 18)) {
            val reader = RangeLockedGate(ByteArray(size).apply { this[8] = 1 })
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, reader, allowPendingControl = true).close() }
            assertTrue(reader.reads.isEmpty())
            assertTrue(reader.fake.handles.all { it.closed })
        }
        val changes: List<(WindowsInstallInfo) -> WindowsInstallInfo> = listOf(
            { it.copy(owner = "S-1-1-0") }, { it.copy(dacl = null) },
            { it.copy(dacl = it.dacl.orEmpty() + WindowsInstallAce(0, 0, 0x40, "S-1-1-0")) },
            { it.copy(attributes = 0x400) }, { it.copy(reparseTag = 1) }, { it.copy(disk = false) },
        )
        for (target in listOf("C:\\Apps", "C:\\ProgramData", "gate-")) for (change in changes) {
            val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1 })
            reader.fake.inspectTransform = { path, info -> if (path.contains(target)) change(info) else info }
            assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, reader, allowPendingControl = true).close() }
            assertTrue(reader.reads.isEmpty())
            assertTrue(reader.fake.handles.all { it.closed })
        }
        val reader = RangeLockedGate(ByteArray(17).apply { this[8] = 1 })
        reader.fake.aclVolume = false
        assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, reader, allowPendingControl = true).close() }
        assertTrue(reader.reads.isEmpty())
        assertTrue(reader.fake.handles.all { it.closed })
    }

    @Test fun readableFullGateRetainsReservedByteValidationAndOtherErrorsNeverFallback() {
        val malformed = RangeLockedGate(ByteArray(17).apply { this[8] = 1; this[16] = 1 }).apply {
            exclusiveRanges.clear()
        }
        assertFails { DesktopWindowsInstallAdmission.enter(LAUNCHER, malformed, allowPendingControl = true).close() }
        assertEquals(listOf(0 to 18), malformed.reads)
        assertTrue(malformed.fake.handles.all { it.closed })
        val denied = RangeLockedGate(ByteArray(17).apply { this[8] = 1 }).apply {
            fullFailure = WindowsInstallNativeFailure(5)
        }
        assertEquals(5, assertFailsWith<WindowsInstallNativeFailure> {
            DesktopWindowsInstallAdmission.enter(LAUNCHER, denied, allowPendingControl = true).close()
        }.code)
        assertEquals(listOf(0 to 18), denied.reads)
        assertTrue(denied.fake.handles.all { it.closed })
    }

    /** ReadFile-style range checking, independent of admission's requested verdict. */
    private class RangeLockedGate(payload: ByteArray, val fake: Fake = Fake().apply { bytes = payload }) :
        WindowsAdmissionNative by fake {
        val exclusiveRanges = mutableListOf(16 until 17)
        val reads = mutableListOf<Pair<Int, Int>>()
        var returnedPrefix: ByteArray? = null
        var prefixFailure: WindowsInstallNativeFailure? = null
        var fullFailure: WindowsInstallNativeFailure? = null
        override fun lockShared(handle: WindowsInstallNative.Handle): Boolean =
            fake.lockShared(handle) && exclusiveRanges.none { 0 in it }
        override fun readGate(handle: WindowsInstallNative.Handle): ByteArray = readRange(0, 18, false)
        override fun readGatePrefix(handle: WindowsInstallNative.Handle): ByteArray = readRange(0, 16, true)
        private fun readRange(offset: Int, count: Int, prefix: Boolean): ByteArray {
            reads += offset to count
            (if (prefix) prefixFailure else fullFailure)?.let { throw it }
            if (exclusiveRanges.any { offset < it.last + 1 && it.first < offset + count }) {
                throw WindowsInstallNativeFailure(33)
            }
            if (prefix) returnedPrefix?.let { return it.copyOf() }
            return fake.bytes.copyOfRange(offset, minOf(offset + count, fake.bytes.size))
        }
    }

    internal class Fake : WindowsAdmissionNative {
        class Handle(val path: String, val gate: Boolean) : WindowsInstallNative.Handle { var closed = false }
        val handles = mutableListOf<Handle>()
        val events = mutableListOf<String>()
        var bytes = ByteArray(17)
        var absentGate = false
        var lockAvailable = true
        var readFailure: Exception? = null
        var directoryFailure: WindowsInstallNativeFailure? = null
        var aclVolume = true
        var childNames = listOf("witness")
        var canonicalTransform: (String) -> String = { it }
        var inspectTransform: (String, WindowsInstallInfo) -> WindowsInstallInfo = { _, info -> info }
        var closeFailure: Handle? = null
        override fun currentSid() = SID
        override fun programData() = "C:\\ProgramData"
        override fun openDirectory(path: String): WindowsInstallNative.Handle {
            if (path.endsWith("vpn-control-install-jobs")) directoryFailure?.let { throw it }
            return Handle(path, false).also { handles += it }
        }
        override fun openGate(path: String): WindowsInstallNative.Handle {
            if (absentGate) throw WindowsInstallNativeFailure(2)
            return Handle(path, true).also { handles += it }
        }
        override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
            handle as Handle
            val owner = if (handle.path.startsWith("C:\\Apps")) SID else "S-1-5-18"
            return inspectTransform(handle.path, WindowsInstallInfo(!handle.gate && !handle.path.endsWith(".exe"), owner = owner,
                dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, owner)), size = if (handle.gate) bytes.size.toLong() else 0))
        }
        override fun persistentAcl(handle: WindowsInstallNative.Handle) = aclVolume
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + canonicalTransform((handle as Handle).path)
        override fun children(path: String) = childNames
        override fun invariantUppercase(value: String) = value.uppercase(java.util.Locale.ROOT)
        override fun lockShared(handle: WindowsInstallNative.Handle): Boolean { events += "lock"; return lockAvailable }
        override fun readGate(handle: WindowsInstallNative.Handle): ByteArray { events += "read"; readFailure?.let { throw it }; return bytes.copyOf() }
        override fun unlockShared(handle: WindowsInstallNative.Handle) { events += "unlock" }
        override fun close(handle: WindowsInstallNative.Handle) {
            check(!(handle as Handle).closed)
            if (closeFailure === handle) { closeFailure = null; throw WindowsInstallNativeFailure(32) }
            handle.closed = true
        }
    }
    companion object {
        private val LAUNCHER = Path.of("C:\\Apps\\東京\\vpn-control.exe")
        private const val SID = "S-1-5-21-1-2-3-1001"

        // Exact root descriptor from Windows package run 34151739039, SHA 28c42598.
        // NETWORK SERVICE owns D:\; it is not an installer trust principal.
        private fun runnerVolumeInfo() = WindowsInstallInfo(true, owner = "S-1-5-20", attributes = 22,
            dacl = listOf(
                WindowsInstallAce(0, 3, 2032127, "S-1-5-32-544"),
                WindowsInstallAce(0, 3, 2032127, "S-1-5-18"),
                WindowsInstallAce(0, 11, 268435456, "S-1-3-0"),
                WindowsInstallAce(0, 3, 1179817, "S-1-5-32-545"),
                WindowsInstallAce(0, 2, 4, "S-1-5-32-545"),
                WindowsInstallAce(0, 10, 2, "S-1-5-32-545"),
                WindowsInstallAce(0, 0, 1179817, "S-1-1-0"),
            ))
    }
}
