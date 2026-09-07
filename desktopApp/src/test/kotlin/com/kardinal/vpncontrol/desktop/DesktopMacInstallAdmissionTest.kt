package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopMacInstallAdmissionTest {
    @Test fun firstInstallWithoutAnyGateStillRetainsExecutableSharedAdmission() {
        val fake = Fake().apply { missing = true }
        val lease = DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS)
        assertEquals(listOf(LAUNCHER.toString()), fake.lockedPaths)
        assertTrue(fake.closed.isEmpty())
        lease.close()
        assertEquals(fake.paths.size, fake.closed.size)
    }
    @Test fun nativeAdminGroupWritableAncestorAndDenyOnlyHomeAreAccepted() {
        val fake = Fake().apply {
            adminGid = 123 // Deliberately not the default macOS gid.
            metadata["/Applications"] = info(mode = 0x41fd, gid = 123)
            metadata["/Users/test"] = info(uid = 501, acl = MacAdmissionAcl.DENY_ONLY)
        }
        val roots = ROOTS + MacAdmissionRoot(Path.of("/Users/test/Library/Application Support/vpn-control-install-jobs"), 501)
        fake.metadata[roots.last().path.toString()] = info(uid = 501)
        fake.missing = true
        DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = roots).close()
        assertEquals(fake.paths.size, fake.closed.size)
    }
    @Test fun adminAndAclExceptionsNeverApplyToUntrustedGroupOwnerOrFinalAuthority() {
        for ((path, metadata) in listOf(
            "/Applications" to info(mode = 0x41fd, gid = 124),
            "/Applications" to info(uid = 501, mode = 0x41fd, gid = 123),
            "/Applications" to info(mode = 0x41ff, gid = 123),
            ROOTS.single().path.toString() to info(mode = 0x41fd, gid = 123),
            ROOTS.single().path.toString() to info(acl = MacAdmissionAcl.DENY_ONLY),
            LAUNCHER.toString() to info(mode = 0x81ed, acl = MacAdmissionAcl.DENY_ONLY))) {
            val fake = Fake().apply { adminGid = 123; this.metadata[path] = metadata }
            assertFails { DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS) }
            assertEquals(fake.paths.size, fake.closed.size)
        }
        val unknownGroup = Fake().apply { metadata["/Applications"] = info(mode = 0x41fd, gid = 123) }
        assertFails { DesktopMacInstallAdmission.enter(LAUNCHER, unknownGroup, roots = ROOTS) }
    }
    @Test fun stickyDirectoryExceptionNeverAcceptsWritableExecutable() {
        val fake = Fake().apply { executableMode = 0x83ff } // regular 01777, root-owned
        assertFails { DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS) }
        assertEquals(fake.paths.size, fake.closed.size)
        assertFalse("lock" in fake.events)
    }
    @Test fun pendingControlKeepsExactSharedLockAndReportsOnlyActualPendingByte() {
        for (pending in listOf(false, true)) {
            val fake = Fake().apply { bytes[8] = if (pending) 1 else 0 }
            var callbacks = 0
            val lease = DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS,
                allowPendingControl = true, onPendingControl = { callbacks++ })
            assertEquals(if (pending) 1 else 0, callbacks)
            assertTrue(fake.events.indexOf("lock") < fake.events.indexOf("read"))
            assertTrue(fake.closed.isEmpty())
            lease.close(); lease.close()
            assertEquals(fake.paths.size, fake.closed.size)
        }
    }
    @Test fun normalPendingExclusiveLockMalformedAndUntrustedGateFailClosed() {
        for (fake in listOf(Fake().apply { bytes[8] = 1 }, Fake().apply { available = false },
            Fake().apply { bytes[0] = 1 }, Fake().apply { gateLinks = 2 },
            Fake().apply { gateUid = 502 }, Fake().apply { gateMode = 0x81b6 })) {
            assertFails { DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS) }
            assertEquals(fake.paths.size, fake.closed.size)
        }
        val exclusive = Fake().apply { available = false; bytes[8] = 1 }
        assertFails { DesktopMacInstallAdmission.enter(LAUNCHER, exclusive, roots = ROOTS, allowPendingControl = true) }
    }
    @Test fun missingGateNeverReportsPendingAndDifferentExecutableIsRejected() {
        val fake = Fake().apply { missing = true }
        DesktopMacInstallAdmission.enter(LAUNCHER, fake, roots = ROOTS, allowPendingControl = true,
            onPendingControl = { error("No pending gate") }).close()
        assertEquals(listOf(LAUNCHER.toString()), fake.lockedPaths)
        assertFails { DesktopMacInstallAdmission.enter(Path.of("/Applications/vpn-control.app/Contents/MacOS/other"), Fake(), roots = ROOTS) }
    }
    internal class Fake : MacInstallAdmissionNative {
        val paths = mutableMapOf<Int, String>()
        val closed = mutableSetOf<Int>()
        val events = mutableListOf<String>()
        val lockedPaths = mutableListOf<String>()
        var bytes = ByteArray(17)
        var available = true
        var missing = false
        var gateLinks = 1L
        var gateUid = 0L
        var gateMode = 0x81a4
        var executableMode = 0x81ed
        var adminGid: Long? = null
        val metadata = mutableMapOf<String, MacAdmissionInfo>()
        override fun adminGroupId() = adminGid
        override fun currentUid() = 501L
        override fun currentExecutable() = LAUNCHER.toString()
        override fun homeDirectory() = Path.of("/Users/test")
        override fun openRoot() = add("/")
        override fun openChild(parent: Int, name: String, directory: Boolean, optional: Boolean): Int? {
            if (missing && name.startsWith("gate-")) return null
            return add(paths.getValue(parent).trimEnd('/') + "/" + name)
        }
        private fun add(path: String): Int = (paths.size + 1).also { paths[it] = path }
        override fun inspect(fd: Int): MacAdmissionInfo {
            val path = paths.getValue(fd)
            metadata[path]?.let { return it }
            val gate = path.substringAfterLast('/').startsWith("gate-")
            val file = path.endsWith("/vpn-control") || gate
            return MacAdmissionInfo(if (gate) gateUid else 0, if (gate) gateMode else if (file) executableMode else 0x41ed,
                if (gate) gateLinks else 1, if (gate) bytes.size.toLong() else 0, 1, fd.toLong())
        }
        override fun canonicalPath(fd: Int) = Path.of(paths.getValue(fd))
        override fun lockShared(fd: Int): Boolean { events += "lock"; lockedPaths += paths.getValue(fd); return available }
        override fun readGate(fd: Int): ByteArray { events += "read"; return bytes.copyOf() }
        override fun close(fd: Int) { check(closed.add(fd)) }
    }
    companion object {
        private fun info(uid: Long = 0, mode: Int = 0x41ed, gid: Long = 0, acl: MacAdmissionAcl = MacAdmissionAcl.EMPTY) =
            MacAdmissionInfo(uid, mode, 1, 0, 1, 1, gid, acl)
        val LAUNCHER: Path = Path.of("/Applications/vpn-control.app/Contents/MacOS/vpn-control")
        internal val ROOTS = listOf(MacAdmissionRoot(Path.of("/Library/Application Support/vpn-control-install-jobs"), 0))
    }
}
