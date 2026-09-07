package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopWindowsInstallAdmissionTest {
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
            return inspectTransform(handle.path, WindowsInstallInfo(!handle.gate, owner = owner,
                dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, owner)), size = if (handle.gate) bytes.size.toLong() else 0))
        }
        override fun persistentAcl(handle: WindowsInstallNative.Handle) = aclVolume
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + canonicalTransform((handle as Handle).path)
        override fun children(path: String) = childNames
        override fun invariantUppercase(value: String) = value.uppercase(java.util.Locale.ROOT)
        override fun lockShared(handle: WindowsInstallNative.Handle): Boolean { events += "lock"; return lockAvailable }
        override fun readGate(handle: WindowsInstallNative.Handle): ByteArray { events += "read"; readFailure?.let { throw it }; return bytes.copyOf() }
        override fun unlockShared(handle: WindowsInstallNative.Handle) { events += "unlock" }
        override fun close(handle: WindowsInstallNative.Handle) { check(!(handle as Handle).closed); handle.closed = true }
    }
    companion object {
        private val LAUNCHER = Path.of("C:\\Apps\\東京\\vpn-control.exe")
        private const val SID = "S-1-5-21-1-2-3-1001"
    }
}
